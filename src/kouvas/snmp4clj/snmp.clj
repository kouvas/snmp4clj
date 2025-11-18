(ns kouvas.snmp4clj.snmp
  (:require [kouvas.snmp4clj.ber :as ber]
            [kouvas.snmp4clj.packet :as pack]
            [kouvas.snmp4clj.pdu :as pdu]
            [kouvas.snmp4clj.smi.integer32 :as i32]
            [kouvas.snmp4clj.smi.octet-string :as os]
            [kouvas.snmp4clj.smi.oid :as oid]
            [kouvas.snmp4clj.smi.variable-binding :as vb]
            [kouvas.snmp4clj.socket :as soc]
            [kouvas.snmp4clj.target :as target]
            [kouvas.snmp4clj.utils :as u]
            [kouvas.snmp4clj.validation :as valid]
            [kouvas.snmp4clj.v3.engine :as engine]
            [kouvas.snmp4clj.v3.message :as v3msg]
            [kouvas.snmp4clj.v3.usm :as usm]))

(set! *warn-on-reflection* true)

(def ^:const snmp
  {:snmp/v1  0
   :snmp/v2c 1
   :snmp/v3  3})

(defn execute-request!
  [target payload]
  (try
    (let [out-buffer (byte-array payload)
          socket     (soc/create)
          port       (:port target)
          address    (-> target :address :inet-address)
          out-packet (pack/create out-buffer address port)]
      (soc/timeout! socket (:timeout target))
      (soc/send socket out-packet)
      (let [in-buffer (byte-array (:max-size-request-pdu target))
            in-packet (pack/create in-buffer address port)]
        (soc/receive socket in-packet)
        (let [length (pack/length in-packet)
              bytes  (byte-array length)]
          (System/arraycopy in-buffer 0 bytes 0 length)
          (vec bytes))))
    (catch java.net.SocketTimeoutException e
      (println "No response from server: " (.getMessage e)))
    (catch Exception e
      (println "Error communicating with server: " (.getMessage e)))))

(defn snmp-request
  "Execute an SNMP request to a remote agent.

  Common Parameters:
  - :operation - One of :get, :get-next, :set (v1+) or :get-bulk (v2c+ only)
  - :version - One of :snmp/v1, :snmp/v2c, or :snmp/v3 (default: :snmp/v2c)
  - :host - Target hostname or IP address (default: \"localhost\")
  - :port - SNMP port (default: 161)
  - :oids - Vector of OID strings to query (required)
  - :timeout - Timeout in milliseconds (default: 5000)
  - :transport - :udp (default, only supported option currently)
  - :retries - Number of retries (default: 3)

  v1/v2c Parameters:
  - :community - SNMP community string (required for v1/v2c)

  v3 Parameters (authNoPriv only):
  - :username - SNMPv3 username (required for v3)
  - :auth-protocol - :md5 or :sha (required for v3)
  - :auth-password - Authentication password (required for v3)

  Returns:
  - Vector of BER-encoded bytes on success
  - nil on error (with println to stderr)"
  [& {:keys [operation host oids version community port
             transport timeout retries request-max-pdu-size
             username auth-protocol auth-password]
      :or   {operation            :get
             host                 "localhost"
             version              :snmp/v2c
             timeout              5000
             retries              3
             port                 161
             transport            :udp
             request-max-pdu-size pdu/max-size-request-pdu}
      :as   opts}]

  ;; Validate version and operation
  (valid/validate-version! version)
  (valid/validate-operation! version operation)

  (if (= version :snmp/v3)
    ;; SNMPv3 code path
    (let [;; Validate v3 parameters
          _ (when-not username
              (throw (ex-info "Username required for SNMPv3" {:version version})))
          _ (when-not auth-protocol
              (throw (ex-info "Auth protocol required for SNMPv3" {:version version})))
          _ (when-not auth-password
              (throw (ex-info "Auth password required for SNMPv3" {:version version})))
          _ (when-not (#{:md5 :sha} auth-protocol)
              (throw (ex-info "Auth protocol must be :md5 or :sha" {:protocol auth-protocol})))

          ;; Create send function for this host/port
          send-fn (fn [request-bytes]
                    (let [target (target/make-target host port nil nil timeout retries transport request-max-pdu-size 1 1)]
                      (execute-request! target request-bytes)))

          ;; Discover/sync engine (uses cache if available)
          engine-state (engine/discover-and-sync host port username auth-password auth-protocol send-fn)]

      (when engine-state
        ;; Create authenticated request
        (let [oids (mapv oid/make-oid oids)
              varbinds (vb/make-variable-bindings oids)
              pdu-obj (pdu/make-pdu varbinds operation)

              ;; Get current engine time
              current-time (engine/get-current-engine-time engine-state)

              ;; Create authenticated message
              message (v3msg/make-authenticated-message
                        pdu-obj
                        (:engine-id engine-state)
                        (:engine-boots engine-state)
                        current-time
                        username
                        false)  ; Not reportable for GET requests

              ;; Encode with authentication
              payload (v3msg/encode-snmpv3-message
                        message
                        (:localized-key engine-state)
                        auth-protocol)]

          ;; Send request
          (let [target (target/make-target host port nil nil timeout retries transport request-max-pdu-size 1 1)]
            (execute-request! target payload)))))

    ;; SNMPv1/v2c code path (original)
    (let [community (os/make-octet-string community)
          version   (i32/make-integer32 (get snmp version))
          target    (target/make-target host port version community timeout retries transport request-max-pdu-size 1 1)
          oids      (mapv oid/make-oid oids)
          varbinds  (vb/make-variable-bindings oids)
          pdu       (pdu/make-pdu varbinds operation)
          payload   (ber/encode-snmp-payload version community pdu)]
      (execute-request! target payload))))

(defn ->response
  "Decode SNMP response bytes to a map of OID -> value.

  Supports v1, v2c, and v3 responses.

  Parameters:
  - byte-vec: Vector of response bytes

  Returns: Map of OID strings to values"
  [byte-vec]
  (let [;; Try to detect version by looking at the message structure
        ;; v3 messages have version=3 at the beginning
        version-tlv (ber/bytes->tlv-structure byte-vec)
        first-elem (first (:value version-tlv))
        version-num (when (= 2 (:tag first-elem))  ; INTEGER tag
                      (ber/decode-ber-value first-elem))]

    (if (= 3 version-num)
      ;; SNMPv3 response
      (let [decoded (v3msg/decode-snmpv3-message byte-vec)
            scoped-pdu (:msgData decoded)
            pdu (:data scoped-pdu)]
        (->> (:variable-bindings pdu)
             (map (fn [{:keys [oid variable]}]
                    [(:value oid) (:value variable)]))
             (into {})))

      ;; SNMPv1/v2c response (original)
      (->> byte-vec
           ber/decode-ber
           :pdu
           :variable-bindings
           (map (fn [{:keys [oid variable]}]
                  [(:value oid) (:value variable)]))
           (into {})))))

(comment

  (def bits
    (snmp-request {:operation :get
                   :host      "localhost"
                   :version   :snmp/v2c
                   :transport :udp
                   :port      5161
                   :community "public"
                   :oids      [
                               ;;"1.3.6.1.4.1.2021.4.20.0" ;; private.enterprises.ucdavis.memory.20.0, Counter64
                               ;;"1.3.6.1.2.1.92.1.1.2.0" ;; https://oidref.com/1.3.6.1.2.1.92.1.1.2
                               ;;"1.3.6.1.2.1.1.6.0"     ;; sysLocation, Octet String
                               "1.3.6.1.2.1.1.1.0"     ;; sysDescr, Octet String
                               "1.3.6.1.2.1.1.7.0"     ;; sysServices, Integer
                               ;;"1.3.6.1.2.1.1.2.0"     ;; https://www.alvestrand.no/objectid/1.3.6.1.2.1.1.2.html, OID
                               "1.3.6.1.2.1.1.3.0"     ;; sysUptime, Timeticks
                               "1.3.6.1.4.1.2021.10.1.6.1" ;; opaque, float
                               ]}))
  bits
  ;;=> [48 -127 -113  ;; tag(sequence type), length, value->
  ;;      2 1 1
  ;;      4 6 112 117 98 108 105 99
  ;;      -94 -127 -127 ;; pdu tag, length, value->
  ;;        2 4 45 48 -55 -5
  ;;        2 1 0
  ;;        2 1 0
  ;;        48 115
  ;;          48 56
  ;;            6 8 43 6 1 2 1 1 1 0
  ;;            4 44 83 110 109 112 100 32 116 101 115 116 32 99 111 110 116 97 105 110 101 114 32 102 111 114 32 105 110 116 101 103 114 97 116 105 111 110 32 116 101 115 116 105 110 103
  ;;         48 13
  ;;            6 8 43 6 1 2 1 1 7 0
  ;;            2 1 88
  ;;         48 16
  ;;           6 8 43 6 1 2 1 1 3 0
  ;;           67 4 0 -4 42 -27
  ;;         48 22
  ;;           6 11 43 6 1 4 1 -113 101 10 1 6 1
  ;;           68 7 -97 120 4 61 -115 0 0]

  (map u/->hex-str bits)
  ;;=> ("0x30" "0x81" "0x8F"
  ;;  "0x02" "0x01" "0x01"
  ;;  "0x04" "0x06" "0x70" "0x75" "0x62" "0x6C" "0x69" "0x63"
  ;;  "0xA2" "0x81" "0x81"
  ;;  "0x02" "0x04" "0x2D" "0x30" "0xC9" "0xFB"
  ;;  "0x02" "0x01" "0x00"
  ;;  "0x02" "0x01" "0x00"
  ;;  "0x30" "0x73"
  ;;  "0x30" "0x38" "0x06" "0x08" "0x2B" "0x06" "0x01" "0x02" "0x01" "0x01" "0x01" "0x00" "0x04" "0x2C" "0x53" "0x6E" "0x6D" "0x70" "0x64" "0x20" "0x74" "0x65" "0x73" "0x74" "0x20" "0x63" "0x6F" "0x6E" "0x74" "0x61" "0x69" "0x6E" "0x65" "0x72" "0x20" "0x66" "0x6F" "0x72" "0x20" "0x69" "0x6E" "0x74" "0x65" "0x67" "0x72" "0x61" "0x74" "0x69" "0x6F" "0x6E" "0x20" "0x74" "0x65" "0x73" "0x74" "0x69" "0x6E" "0x67"
  ;;  "0x30" "0x0D" "0x06" "0x08" "0x2B" "0x06" "0x01" "0x02" "0x01" "0x01" "0x07" "0x00" "0x02" "0x01" "0x58"
  ;;  "0x30" "0x10" "0x06" "0x08" "0x2B" "0x06" "0x01" "0x02" "0x01" "0x01" "0x03" "0x00" "0x43" "0x04" "0x00" "0xFC" "0x2A" "0xE5"
  ;;  "0x30" "0x16" "0x06" "0x0B" "0x2B" "0x06" "0x01" "0x04" "0x01" "0x8F" "0x65" "0x0A" "0x01" "0x06" "0x01" "0x44" "0x07" "0x9F" "0x78" "0x04" "0x3D" "0x8D" "0x00" "0x00")

  (ber/bytes->tlv-structure bits)
  ;;=>
  ;;{:tag 48,
  ;; :length 143,
  ;; :value [{:tag 2, :length 1, :value [1]}
  ;;         {:tag 4, :length 6, :value [112 117 98 108 105 99]}
  ;;         {:tag -94,
  ;;          :length 129,
  ;;          :value [{:tag 2, :length 4, :value [45 48 -55 -5]}
  ;;                  {:tag 2, :length 1, :value [0]}
  ;;                  {:tag 2, :length 1, :value [0]}
  ;;                  {:tag 48,
  ;;                   :length 115,
  ;;                   :value [{:tag 48,
  ;;                            :length 56,
  ;;                            :value [{:tag 6, :length 8, :value [43 6 1 2 1 1 1 0]}
  ;;                                    {:tag 4,
  ;;                                     :length 44,
  ;;                                     :value [83 110 109 112 100 32 116 101 115 116 32 99 111 110 116 97 105 110 101 114 32 102
  ;;                                             111 114 32 105 110 116 101 103 114 97 116 105 111 110 32 116 101 115 116 105 110 103]}]}
  ;;                           {:tag 48,
  ;;                            :length 13,
  ;;                            :value [{:tag 6, :length 8, :value [43 6 1 2 1 1 7 0]} {:tag 2, :length 1, :value [88]}]}
  ;;                           {:tag 48,
  ;;                            :length 16,
  ;;                            :value [{:tag 6, :length 8, :value [43 6 1 2 1 1 3 0]}
  ;;                                    {:tag 67, :length 4, :value [0 -4 42 -27]}]}
  ;;                           {:tag 48,
  ;;                            :length 22,
  ;;                            :value [{:tag 6, :length 11, :value [43 6 1 4 1 -113 101 10 1 6 1]}
  ;;                                    {:tag 68, :length 7, :value [-97 120 4 61 -115 0 0]}]}]}]}]}

  (ber/decode-ber-bytes bits)
  ;;=>
  ;;{:version :snmp/v2c,
  ;; :community "public",
  ;; :pdu {:type :response,
  ;;       :request-id 758172155,
  ;;       :error-status :no-error,
  ;;       :error-index 0,
  ;;       :variable-bindings [{:oid {:value "1.3.6.1.2.1.1.1.0", :type :ber/oid},
  ;;                            :variable {:value "Snmpd test container for integration testing", :type :ber/octet-string}}
  ;;                           {:oid {:value "1.3.6.1.2.1.1.7.0", :type :ber/oid},
  ;;                            :variable {:value 88, :type :ber/integer}}
  ;;                           {:oid {:value "1.3.6.1.2.1.1.3.0", :type :ber/oid},
  ;;                            :variable {:value "1 day, 21:54:20.53", :type :ber/timeticks}}
  ;;                           {:oid {:value "1.3.6.1.4.1.2021.10.1.6.1", :type :ber/oid},
  ;;                            :variable {:value 0.068847656, :type :ber/opaque-float}}]}}

  (->response bits)
  ;;=>
  ;;{"1.3.6.1.2.1.1.1.0" "Snmpd test container for integration testing",
  ;; "1.3.6.1.2.1.1.7.0" 88,
  ;; "1.3.6.1.2.1.1.3.0" "1 day, 21:54:20.53",
  ;; "1.3.6.1.4.1.2021.10.1.6.1" 0.068847656}

  )