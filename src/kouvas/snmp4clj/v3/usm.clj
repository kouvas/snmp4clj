(ns kouvas.snmp4clj.v3.usm
  "SNMPv3 User-based Security Model (USM) parameters.

  Implements RFC 3414 USM security parameters structure."
  (:require [kouvas.snmp4clj.ber :as ber]
            [kouvas.snmp4clj.smi.integer32 :as i32]
            [kouvas.snmp4clj.smi.octet-string :as os]))

;; ============================================================================
;; USM Security Parameters Structure (RFC 3414 Section 2.4)
;; ============================================================================

(defrecord UsmSecurityParameters
  [msgAuthoritativeEngineID      ; OCTET STRING (5-32 bytes)
   msgAuthoritativeEngineBoots   ; INTEGER (0..2147483647)
   msgAuthoritativeEngineTime    ; INTEGER (0..2147483647)
   msgUserName                   ; OCTET STRING (0-32 bytes)
   msgAuthenticationParameters   ; OCTET STRING (12 bytes for HMAC, 0 for noAuth)
   msgPrivacyParameters])        ; OCTET STRING (empty for authNoPriv)

(defn make-usm-parameters
  "Create USM security parameters.

  Parameters:
  - engine-id: Authoritative engine ID bytes (5-32 bytes)
  - engine-boots: Engine boots counter (default 0)
  - engine-time: Engine time in seconds (default 0)
  - username: User name string (0-32 chars)
  - auth-params: Authentication parameters (12 bytes for HMAC, empty for discovery)
  - priv-params: Privacy parameters (empty for authNoPriv)

  Returns: UsmSecurityParameters record"
  ([engine-id username]
   (make-usm-parameters engine-id 0 0 username (byte-array 12) (byte-array 0)))
  ([engine-id engine-boots engine-time username]
   (make-usm-parameters engine-id engine-boots engine-time username (byte-array 12) (byte-array 0)))
  ([engine-id engine-boots engine-time username auth-params priv-params]
   (->UsmSecurityParameters
     (if (bytes? engine-id) engine-id (byte-array engine-id))
     (int engine-boots)
     (int engine-time)
     username
     (if (bytes? auth-params) auth-params (byte-array auth-params))
     (if (bytes? priv-params) priv-params (byte-array priv-params)))))

;; ============================================================================
;; USM Parameters Encoding (RFC 3414 Section 2.4)
;; ============================================================================

(defn encode-usm-parameters
  "Encode USM parameters to BER SEQUENCE, then wrap in OCTET STRING.

  The structure is:
  OCTET STRING {
    SEQUENCE {
      msgAuthoritativeEngineID     OCTET STRING
      msgAuthoritativeEngineBoots  INTEGER
      msgAuthoritativeEngineTime   INTEGER
      msgUserName                  OCTET STRING
      msgAuthenticationParameters  OCTET STRING
      msgPrivacyParameters         OCTET STRING
    }
  }

  Returns: Vector of bytes (outer OCTET STRING containing encoded SEQUENCE)"
  [usm-params]
  (let [engine-id-bytes   (:msgAuthoritativeEngineID usm-params)
        engine-boots      (:msgAuthoritativeEngineBoots usm-params)
        engine-time       (:msgAuthoritativeEngineTime usm-params)
        username          (:msgUserName usm-params)
        auth-params       (:msgAuthenticationParameters usm-params)
        priv-params       (:msgPrivacyParameters usm-params)

        ;; Encode each field
        encoded-engine-id  (ber/encode-ber (os/make-octet-string engine-id-bytes))
        encoded-boots      (ber/encode-ber (i32/make-integer32 engine-boots))
        encoded-time       (ber/encode-ber (i32/make-integer32 engine-time))
        encoded-username   (ber/encode-ber (os/make-octet-string username))
        encoded-auth       (ber/encode-ber (os/make-octet-string auth-params))
        encoded-priv       (ber/encode-ber (os/make-octet-string priv-params))

        ;; Build SEQUENCE
        usm-sequence       (ber/encode-sequence
                             [encoded-engine-id
                              encoded-boots
                              encoded-time
                              encoded-username
                              encoded-auth
                              encoded-priv])

        ;; Wrap in OCTET STRING (convert vector to byte-array)
        outer-octet-string (ber/encode-ber (os/make-octet-string (byte-array usm-sequence)))]
    outer-octet-string))

;; ============================================================================
;; USM Parameters Decoding
;; ============================================================================

(defn decode-usm-parameters
  "Decode USM parameters from BER bytes.

  Expects OCTET STRING containing a SEQUENCE of USM fields.

  Returns: UsmSecurityParameters record"
  [bytes]
  (let [;; First decode outer OCTET STRING
        outer-tlv       (ber/bytes->tlv-structure bytes)
        _               (when-not (= 0x04 (:tag outer-tlv))
                          (throw (ex-info "Expected OCTET STRING for USM parameters"
                                          {:tag (:tag outer-tlv)})))

        ;; Decode inner SEQUENCE
        inner-bytes     (:value outer-tlv)
        inner-tlv       (ber/bytes->tlv-structure inner-bytes)
        _               (when-not (= 0x30 (:tag inner-tlv))
                          (throw (ex-info "Expected SEQUENCE in USM parameters"
                                          {:tag (:tag inner-tlv)})))

        ;; Extract the 6 fields
        [engine-id-tlv boots-tlv time-tlv username-tlv auth-tlv priv-tlv] (:value inner-tlv)

        ;; Decode each field
        engine-id       (:value engine-id-tlv)  ; Keep as bytes
        engine-boots    (ber/decode-ber-value boots-tlv)
        engine-time     (ber/decode-ber-value time-tlv)
        username        (ber/decode-ber-value username-tlv)
        auth-params     (:value auth-tlv)  ; Keep as bytes
        priv-params     (:value priv-tlv)] ; Keep as bytes

    (->UsmSecurityParameters
      (byte-array engine-id)
      engine-boots
      engine-time
      username
      (byte-array auth-params)
      (byte-array priv-params))))

;; ============================================================================
;; Discovery Request Helpers
;; ============================================================================

(defn make-discovery-usm-parameters
  "Create USM parameters for engine ID discovery request.

  Discovery requests have:
  - Empty engine ID (0 bytes)
  - Engine boots = 0
  - Engine time = 0
  - Empty username
  - Empty auth parameters
  - Empty priv parameters"
  []
  (make-usm-parameters
    (byte-array 0)  ; Empty engine ID
    0               ; Engine boots
    0               ; Engine time
    ""              ; Empty username
    (byte-array 0)  ; Empty auth params
    (byte-array 0))) ; Empty priv params

(defn discovery-request?
  "Check if USM parameters indicate a discovery request.

  Discovery requests have empty engine ID."
  [usm-params]
  (zero? (alength (:msgAuthoritativeEngineID usm-params))))

;; ============================================================================
;; Validation
;; ============================================================================

(defn validate-usm-parameters!
  "Validate USM parameters according to RFC 3414.

  Checks:
  - Engine ID length (5-32 bytes, or 0 for discovery)
  - Username length (0-32 bytes)
  - Authentication parameters length (0 or 12 bytes)
  - Engine boots and time are non-negative"
  [usm-params]
  (let [engine-id-len (alength (:msgAuthoritativeEngineID usm-params))
        username-len  (count (:msgUserName usm-params))
        auth-len      (alength (:msgAuthenticationParameters usm-params))
        boots         (:msgAuthoritativeEngineBoots usm-params)
        time          (:msgAuthoritativeEngineTime usm-params)]

    ;; Engine ID length (0 for discovery, 5-32 otherwise)
    (when-not (or (zero? engine-id-len)
                  (and (>= engine-id-len 5)
                       (<= engine-id-len 32)))
      (throw (ex-info "Invalid engine ID length"
                      {:length engine-id-len
                       :valid  "0 (discovery) or 5-32 bytes"})))

    ;; Username length
    (when (> username-len 32)
      (throw (ex-info "Username too long"
                      {:length username-len
                       :max    32})))

    ;; Auth parameters length (0 for noAuth/discovery, 12 for HMAC)
    (when-not (or (zero? auth-len) (= 12 auth-len))
      (throw (ex-info "Invalid authentication parameters length"
                      {:length auth-len
                       :valid  "0 (noAuth/discovery) or 12 (HMAC)"})))

    ;; Boots and time non-negative
    (when (neg? boots)
      (throw (ex-info "Engine boots cannot be negative"
                      {:boots boots})))

    (when (neg? time)
      (throw (ex-info "Engine time cannot be negative"
                      {:time time})))

    true))

;; ============================================================================
;; Utility Functions
;; ============================================================================

(defn update-auth-params
  "Update authentication parameters in USM parameters.

  Used after HMAC calculation to insert the authentication digest."
  [usm-params auth-params]
  (assoc usm-params :msgAuthenticationParameters auth-params))

(defn zero-auth-params
  "Set authentication parameters to 12 zero bytes.

  Used before HMAC calculation."
  [usm-params]
  (assoc usm-params :msgAuthenticationParameters (byte-array 12)))

(defn usm-parameters->map
  "Convert USM parameters to a map for debugging/logging."
  [usm-params]
  {:engine-id       (vec (:msgAuthoritativeEngineID usm-params))
   :engine-boots    (:msgAuthoritativeEngineBoots usm-params)
   :engine-time     (:msgAuthoritativeEngineTime usm-params)
   :username        (:msgUserName usm-params)
   :auth-params-len (alength (:msgAuthenticationParameters usm-params))
   :priv-params-len (alength (:msgPrivacyParameters usm-params))})

(comment
  ;; Create discovery USM parameters
  (def discovery-usm (make-discovery-usm-parameters))
  (encode-usm-parameters discovery-usm)

  ;; Create authenticated USM parameters
  (def auth-usm (make-usm-parameters
                  [0x80 0x00 0x1f 0x88 0x03 0x01 0x02 0x03 0x04]
                  5
                  123456
                  "admin"))
  (validate-usm-parameters! auth-usm)
  (encode-usm-parameters auth-usm)

  ;; Round-trip encoding/decoding
  (def encoded (encode-usm-parameters auth-usm))
  (def decoded (decode-usm-parameters encoded))
  (usm-parameters->map decoded)
  )
