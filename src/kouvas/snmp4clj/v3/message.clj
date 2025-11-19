(ns kouvas.snmp4clj.v3.message
  "SNMPv3 message structure encoding and decoding.

  Implements RFC 3412 message format."
  (:require [kouvas.snmp4clj.ber :as ber]
            [kouvas.snmp4clj.smi.integer32 :as i32]
            [kouvas.snmp4clj.smi.octet-string :as os]
            [kouvas.snmp4clj.v3.usm :as usm]
            [kouvas.snmp4clj.v3.crypto :as crypto]))

;; ============================================================================
;; Constants
;; ============================================================================

(def ^:const snmp-version-3 3)
(def ^:const usm-security-model 3)

;; msgFlags bit positions
(def ^:const flag-auth-bit 0)  ; Bit 0: Authentication
(def ^:const flag-priv-bit 1)  ; Bit 1: Privacy/Encryption
(def ^:const flag-report-bit 2) ; Bit 2: Reportable

;; Security levels
(def security-levels
  {:no-auth-no-priv 0x00  ; 00000000
   :auth-no-priv    0x01  ; 00000001
   :auth-priv       0x03}) ; 00000011

;; ============================================================================
;; Message Flags
;; ============================================================================

(defn make-msg-flags
  "Create msgFlags byte based on security level and reportable flag.

  Security levels:
  - :no-auth-no-priv -> 0x00
  - :auth-no-priv    -> 0x01 (auth bit set)
  - :auth-priv       -> 0x03 (auth and priv bits set)

  Reportable flag:
  - Set for discovery and initial requests
  - Clear for confirmed requests (GET, SET)

  Returns: byte"
  [security-level reportable?]
  (let [base-flags (get security-levels security-level 0x00)
        flags      (if reportable?
                     (bit-or base-flags (bit-shift-left 1 flag-report-bit))
                     base-flags)]
    (unchecked-byte flags)))

(defn parse-msg-flags
  "Parse msgFlags byte into security level and reportable flag.

  Returns: {:security-level :auth-no-priv, :reportable? true}"
  [flags-byte]
  (let [flags       (bit-and flags-byte 0xFF)
        auth?       (bit-test flags flag-auth-bit)
        priv?       (bit-test flags flag-priv-bit)
        reportable? (bit-test flags flag-report-bit)
        sec-level   (cond
                      (and auth? priv?) :auth-priv
                      auth?             :auth-no-priv
                      :else             :no-auth-no-priv)]
    {:security-level sec-level
     :reportable?    reportable?}))

;; ============================================================================
;; HeaderData Structure (RFC 3412 Section 6)
;; ============================================================================

(defrecord HeaderData
  [msgID              ; INTEGER (0..2147483647) - request ID
   msgMaxSize         ; INTEGER (484..2147483647) - max message size
   msgFlags           ; OCTET STRING (1 byte) - security flags
   msgSecurityModel]) ; INTEGER (3 for USM)

(defn make-header-data
  "Create SNMPv3 HeaderData.

  Parameters:
  - msg-id: Message ID (unique per request)
  - msg-max-size: Maximum message size agent can accept (default 65507)
  - security-level: :no-auth-no-priv, :auth-no-priv, or :auth-priv
  - reportable?: Whether this message expects a report response
  - security-model: Security model (default 3 for USM)

  Returns: HeaderData record"
  ([msg-id security-level reportable?]
   (make-header-data msg-id 65507 security-level reportable? usm-security-model))
  ([msg-id msg-max-size security-level reportable? security-model]
   (let [flags (make-msg-flags security-level reportable?)]
     (->HeaderData
       (int msg-id)
       (int msg-max-size)
       flags
       (int security-model)))))

(defn encode-header-data
  "Encode HeaderData to BER SEQUENCE.

  Returns: Vector of bytes"
  [header-data]
  (let [encoded-id       (ber/encode-ber (i32/make-integer32 (:msgID header-data)))
        encoded-max-size (ber/encode-ber (i32/make-integer32 (:msgMaxSize header-data)))
        encoded-flags    (ber/encode-ber (os/make-octet-string (byte-array [(:msgFlags header-data)])))
        encoded-model    (ber/encode-ber (i32/make-integer32 (:msgSecurityModel header-data)))]
    (ber/encode-sequence [encoded-id encoded-max-size encoded-flags encoded-model])))

(defn decode-header-data
  "Decode HeaderData from BER SEQUENCE TLV.

  Returns: HeaderData record"
  [tlv]
  (let [[id-tlv max-size-tlv flags-tlv model-tlv] (:value tlv)
        msg-id         (ber/decode-ber-value id-tlv)
        msg-max-size   (ber/decode-ber-value max-size-tlv)
        flags-bytes    (:value flags-tlv)
        msg-flags      (first flags-bytes)
        security-model (ber/decode-ber-value model-tlv)]
    (->HeaderData msg-id msg-max-size msg-flags security-model)))

;; ============================================================================
;; ScopedPDU Structure (RFC 3412 Section 6)
;; ============================================================================

(defrecord ScopedPDU
  [contextEngineID  ; OCTET STRING (usually same as authoritative engine ID)
   contextName      ; OCTET STRING (default "", admin-defined context)
   data])           ; PDU (GetRequest, Response, etc.)

(defn make-scoped-pdu
  "Create ScopedPDU.

  Parameters:
  - context-engine-id: Context engine ID bytes (default empty, uses authoritative)
  - context-name: Context name string (default empty string)
  - pdu: The actual PDU (from pdu/make-pdu)

  Returns: ScopedPDU record"
  ([pdu]
   (make-scoped-pdu (byte-array 0) "" pdu))
  ([context-engine-id context-name pdu]
   (->ScopedPDU
     (if (bytes? context-engine-id) context-engine-id (byte-array context-engine-id))
     context-name
     pdu)))

(defn encode-scoped-pdu
  "Encode ScopedPDU to BER SEQUENCE.

  Returns: Vector of bytes"
  [scoped-pdu]
  (let [encoded-context-id   (ber/encode-ber (os/make-octet-string (:contextEngineID scoped-pdu)))
        encoded-context-name (ber/encode-ber (os/make-octet-string (:contextName scoped-pdu)))
        encoded-pdu          (ber/encode-ber (:data scoped-pdu))]
    (ber/encode-sequence [encoded-context-id encoded-context-name encoded-pdu])))

(defn decode-scoped-pdu
  "Decode ScopedPDU from BER SEQUENCE TLV.

  Returns: ScopedPDU record"
  [tlv]
  (let [[context-id-tlv context-name-tlv pdu-tlv] (:value tlv)
        context-id   (ber/decode-ber-value context-id-tlv)
        context-name (ber/decode-ber-value context-name-tlv)
        pdu          (ber/decode-pdu pdu-tlv)]
    (->ScopedPDU
      (.getBytes context-id "ISO-8859-1")
      context-name
      pdu)))

;; ============================================================================
;; Complete SNMPv3 Message Structure
;; ============================================================================

(defrecord SNMPv3Message
  [msgVersion              ; INTEGER (3)
   msgGlobalData           ; HeaderData SEQUENCE
   msgSecurityParameters   ; OCTET STRING (containing USM params)
   msgData])               ; ScopedPduData (plaintext ScopedPDU for authNoPriv)

(defn make-snmpv3-message
  "Create complete SNMPv3 message.

  Parameters:
  - header-data: HeaderData record
  - usm-parameters: UsmSecurityParameters record
  - scoped-pdu: ScopedPDU record

  Returns: SNMPv3Message record"
  [header-data usm-parameters scoped-pdu]
  (->SNMPv3Message
    snmp-version-3
    header-data
    usm-parameters
    scoped-pdu))

;; ============================================================================
;; Message Encoding
;; ============================================================================

(defn encode-snmpv3-message
  "Encode complete SNMPv3 message to BER.

  For authNoPriv:
  1. Encode all components with zero auth params
  2. Calculate HMAC over entire message
  3. Replace zero auth params with HMAC
  4. Return final message

  Parameters:
  - message: SNMPv3Message record
  - localized-key: For HMAC calculation (nil for noAuth)
  - auth-protocol: :md5 or :sha (nil for noAuth)

  Returns: Vector of bytes (complete message)"
  [message localized-key auth-protocol]
  (let [;; Encode version
        encoded-version (ber/encode-ber (i32/make-integer32 (:msgVersion message)))

        ;; Encode HeaderData
        encoded-header  (encode-header-data (:msgGlobalData message))]

    ;; If authentication required, calculate HMAC
    (if (and localized-key auth-protocol)
      (let [;; For auth, use zero auth params for HMAC calculation
            usm-with-zeros  (usm/zero-auth-params (:msgSecurityParameters message))
            encoded-usm     (usm/encode-usm-parameters usm-with-zeros)

            ;; Encode ScopedPDU
            encoded-scoped  (encode-scoped-pdu (:msgData message))

            ;; Build message with zero auth params for HMAC calculation
            temp-message    (ber/encode-sequence [encoded-version encoded-header encoded-usm encoded-scoped])

            ;; Calculate HMAC over temp message
            hmac            (crypto/calculate-hmac (byte-array temp-message) localized-key auth-protocol)

            ;; Update USM params with calculated HMAC
            usm-with-hmac   (usm/update-auth-params usm-with-zeros hmac)
            encoded-usm-hmac (usm/encode-usm-parameters usm-with-hmac)

            ;; Rebuild final message with HMAC
            final-message   (ber/encode-sequence [encoded-version encoded-header encoded-usm-hmac encoded-scoped])]
        final-message)

      ;; No authentication - use USM params as-is (keep empty auth params)
      (let [encoded-usm    (usm/encode-usm-parameters (:msgSecurityParameters message))
            encoded-scoped (encode-scoped-pdu (:msgData message))]
        (ber/encode-sequence [encoded-version encoded-header encoded-usm encoded-scoped])))))

;; ============================================================================
;; Message Decoding
;; ============================================================================

(defn decode-snmpv3-message
  "Decode complete SNMPv3 message from BER bytes.

  Returns: SNMPv3Message record"
  [bytes]
  (let [;; Parse top-level SEQUENCE
        tlv (ber/bytes->tlv-structure bytes)
        _   (when-not (= 0x30 (:tag tlv))
              (throw (ex-info "Expected SEQUENCE for SNMPv3 message"
                              {:tag (:tag tlv)})))

        ;; Extract components
        [version-tlv header-tlv usm-tlv scoped-tlv] (:value tlv)

        ;; Decode each component
        version       (ber/decode-ber-value version-tlv)
        _             (when-not (= 3 version)
                        (throw (ex-info "Invalid SNMP version for v3 message"
                                        {:version version})))

        header-data   (decode-header-data header-tlv)
        usm-params    (usm/decode-usm-parameters (vec (concat [(:tag usm-tlv) (:length usm-tlv)] (:value usm-tlv))))
        scoped-pdu    (decode-scoped-pdu scoped-tlv)]

    (->SNMPv3Message version header-data usm-params scoped-pdu)))

;; ============================================================================
;; Convenience Functions
;; ============================================================================

(defn generate-msg-id
  "Generate random message ID (0..2147483647)."
  []
  (rand-int Integer/MAX_VALUE))

(defn make-discovery-message
  "Create engine discovery request message.

  Discovery messages have:
  - Empty USM parameters
  - Reportable flag set
  - Empty/minimal PDU

  Parameters:
  - pdu: PDU to send (typically GetRequest)

  Returns: SNMPv3Message record"
  [pdu]
  (let [msg-id      (generate-msg-id)
        header      (make-header-data msg-id :no-auth-no-priv true)
        usm-params  (usm/make-discovery-usm-parameters)
        scoped-pdu  (make-scoped-pdu pdu)]
    (make-snmpv3-message header usm-params scoped-pdu)))

(defn make-authenticated-message
  "Create authenticated message (authNoPriv).

  Parameters:
  - pdu: PDU to send
  - engine-id: Authoritative engine ID
  - engine-boots: Engine boots counter
  - engine-time: Engine time
  - username: SNMP v3 username
  - reportable?: Whether to expect report response

  Returns: SNMPv3Message record (without HMAC - call encode-snmpv3-message with key)"
  [pdu engine-id engine-boots engine-time username reportable?]
  (let [msg-id      (generate-msg-id)
        header      (make-header-data msg-id :auth-no-priv reportable?)
        usm-params  (usm/make-usm-parameters engine-id engine-boots engine-time username)
        scoped-pdu  (make-scoped-pdu pdu)]
    (make-snmpv3-message header usm-params scoped-pdu)))

(comment
  (require '[kouvas.snmp4clj.pdu :as pdu]
           '[kouvas.snmp4clj.smi.oid :as oid]
           '[kouvas.snmp4clj.smi.variable-binding :as vb])

  ;; Create discovery message
  (def test-pdu (pdu/make-pdu
                  (vb/make-variable-bindings
                    [(oid/make-oid "1.3.6.1.2.1.1.1.0")])))

  (def discovery-msg (make-discovery-message test-pdu))
  (def encoded-discovery (encode-snmpv3-message discovery-msg nil nil))
  (println "Encoded discovery:" (count encoded-discovery) "bytes")

  ;; Create authenticated message
  (def auth-msg (make-authenticated-message
                  test-pdu
                  [0x80 0x00 0x1f 0x88 0x03 0x01 0x02 0x03 0x04]
                  5
                  123456
                  "admin"
                  false))

  ;; Encode with authentication
  (def localized-key (crypto/password-to-localized-key
                       "secret123"
                       (byte-array [0x80 0x00 0x1f 0x88 0x03 0x01 0x02 0x03 0x04])
                       :md5))

  (def encoded-auth (encode-snmpv3-message auth-msg localized-key :md5))
  (println "Encoded authenticated:" (count encoded-auth) "bytes")

  ;; Decode message
  (def decoded-msg (decode-snmpv3-message encoded-auth))
  (println "Decoded successfully:" (= 3 (:msgVersion decoded-msg)))
  )
