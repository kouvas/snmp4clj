Messing around with SNMP and Clojure with a proof of concept. 
See [doc](./doc/BER.md) for documentation on Basic Encoding Rules of ASN.1 
protocol that SNMP follows.

A no dependency client that works with SNMP version 2c. Standard Clojure data types, no mutability, minimum working implementation.

```clojure
;; snmp GET request for multiple OIDs
(def bytes-response
  (snmp-request {:operation :get
                 :host      "localhost"
                 :version   :snmp/v2c
                 :transport :udp
                 :port      5161
                 :community "public"
                 :oids      ["1.3.6.1.2.1.1.1.0"     ;; sysDescr, Octet String
                             "1.3.6.1.2.1.1.7.0"     ;; sysServices, Integer
                             "1.3.6.1.2.1.1.3.0"     ;; sysUptime, Timeticks
                             "1.3.6.1.4.1.2021.10.1.6.1" ;; opaque, float
                             ]}))
bytes-response
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

(map u/->hex-str bytes-response)
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

;; recursively parse bytes into T.L.V format
(ber/bytes->tlv-structure bytes-response)
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

(ber/decode-ber-bytes bytes-response)
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

(->response bytes-response)
;;=>
;;{"1.3.6.1.2.1.1.1.0" "Snmpd test container for integration testing",
;; "1.3.6.1.2.1.1.7.0" 88,
;; "1.3.6.1.2.1.1.3.0" "1 day, 21:54:20.53",
;; "1.3.6.1.4.1.2021.10.1.6.1" 0.068847656}

```