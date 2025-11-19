(ns kouvas.snmp4clj.v3.crypto
  "SNMPv3 cryptographic operations for authentication.

  Implements:
  - Password-to-key localization (RFC 3414)
  - HMAC-MD5 and HMAC-SHA1 authentication"
  (:import [javax.crypto Mac]
           [javax.crypto.spec SecretKeySpec]
           [java.security MessageDigest]
           [java.util Arrays]))

;; ============================================================================
;; Key Localization (RFC 3414 Section 2.6)
;; ============================================================================

(def ^:const one-megabyte 1048576)

(defn password-to-key
  "Generate Ku (user key) from password using specified hash algorithm.

  Algorithm (RFC 3414):
  1. Repeat password to fill 1MB buffer
  2. Hash the buffer to produce Ku

  Parameters:
  - password: User password string
  - algorithm: :md5 or :sha (hash algorithm)

  Returns: Ku byte array (16 bytes for MD5, 20 bytes for SHA)"
  [password algorithm]
  (let [password-bytes (.getBytes password "UTF-8")
        password-len   (alength password-bytes)
        buffer         (byte-array one-megabyte)
        hash-algo      (case algorithm
                         :md5 "MD5"
                         :sha "SHA-1"
                         (throw (ex-info "Unsupported hash algorithm"
                                         {:algorithm algorithm
                                          :supported #{:md5 :sha}})))]

    ;; Fill 1MB buffer by repeating password
    ;; Handle empty password - buffer remains all zeros
    (when (pos? password-len)
      (loop [offset 0]
        (when (< offset one-megabyte)
          (let [remaining   (- one-megabyte offset)
                copy-length (min password-len remaining)]
            (System/arraycopy password-bytes 0 buffer offset copy-length)
            (recur (+ offset copy-length))))))

    ;; Hash the buffer to produce Ku
    (let [md (MessageDigest/getInstance hash-algo)]
      (.digest md buffer))))

(defn localize-key
  "Localize Ku with engine ID to produce Kul (localized key).

  Algorithm (RFC 3414):
  Kul = hash(Ku || engineID || Ku)

  Parameters:
  - ku: User key from password-to-key
  - engine-id: Authoritative engine ID bytes
  - algorithm: :md5 or :sha

  Returns: Kul byte array (localized key)"
  [ku engine-id algorithm]
  (let [hash-algo (case algorithm
                    :md5 "MD5"
                    :sha "SHA-1"
                    (throw (ex-info "Unsupported hash algorithm"
                                    {:algorithm algorithm
                                     :supported #{:md5 :sha}})))
        md        (MessageDigest/getInstance hash-algo)]

    ;; Hash: Ku || engineID || Ku
    (.update md ku)
    (.update md engine-id)
    (.update md ku)
    (.digest md)))

(defn password-to-localized-key
  "One-step conversion from password to localized authentication key.

  Convenience function that combines password-to-key and localize-key.

  Parameters:
  - password: User password string
  - engine-id: Authoritative engine ID bytes
  - algorithm: :md5 or :sha

  Returns: Localized authentication key (Kul)"
  [password engine-id algorithm]
  (let [ku (password-to-key password algorithm)]
    (localize-key ku engine-id algorithm)))

;; ============================================================================
;; HMAC Authentication (RFC 3414 Section 6)
;; ============================================================================

(def ^:const hmac-output-length 12)

(defn calculate-hmac
  "Calculate HMAC over message using localized key.

  Returns first 12 bytes of HMAC result as per RFC 3414.

  Parameters:
  - message: Complete SNMPv3 message bytes
  - localized-key: Kul from password-to-localized-key
  - algorithm: :md5 or :sha

  Returns: 12-byte authentication parameters"
  [message localized-key algorithm]
  (let [hmac-algo (case algorithm
                    :md5 "HmacMD5"
                    :sha "HmacSHA1"
                    (throw (ex-info "Unsupported HMAC algorithm"
                                    {:algorithm algorithm
                                     :supported #{:md5 :sha}})))
        mac       (Mac/getInstance hmac-algo)
        key-spec  (SecretKeySpec. localized-key hmac-algo)]

    (.init mac key-spec)
    (let [hmac-result (.doFinal mac message)]
      ;; Return first 12 bytes only
      (Arrays/copyOf hmac-result hmac-output-length))))

(defn verify-hmac
  "Verify HMAC authentication parameters in received message.

  Parameters:
  - message: Complete SNMPv3 message bytes (with auth params as zeros)
  - received-hmac: 12-byte authentication parameters from message
  - localized-key: Kul for verification
  - algorithm: :md5 or :sha

  Returns: true if valid, false otherwise"
  [message received-hmac localized-key algorithm]
  (let [calculated-hmac (calculate-hmac message localized-key algorithm)]
    (Arrays/equals received-hmac calculated-hmac)))

;; ============================================================================
;; Utility Functions
;; ============================================================================

(defn zero-auth-params
  "Create 12 zero bytes for initial msgAuthenticationParameters.

  Used when building message before HMAC calculation."
  []
  (byte-array hmac-output-length))

(defn key-length
  "Get expected key length for algorithm.

  Returns:
  - 16 bytes for MD5
  - 20 bytes for SHA"
  [algorithm]
  (case algorithm
    :md5 16
    :sha 20
    (throw (ex-info "Unsupported algorithm"
                    {:algorithm algorithm}))))

;; ============================================================================
;; Test Vectors (RFC 3414 Appendix A)
;; ============================================================================

(comment
  ;; Test vector from RFC 3414 Appendix A.3.1
  (def test-password "maplesyrup")
  (def test-engine-id (byte-array [0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
                                    0x00 0x00 0x00 0x02]))

  ;; Generate Ku (should match RFC test vector)
  (def ku-md5 (password-to-key test-password :md5))
  (println "Ku (MD5):" (map #(format "%02x" %) ku-md5))
  ;; Expected: 9f af 32 83 88 4e 92 83 4e bc 98 47 d8 ed d9 63

  (def ku-sha (password-to-key test-password :sha))
  (println "Ku (SHA):" (map #(format "%02x" %) ku-sha))
  ;; Expected: 9f b5 cc 03 81 49 7b 37 93 52 89 39 ff 78 8d 5d 79 14 52 11

  ;; Generate Kul (localized key)
  (def kul-md5 (localize-key ku-md5 test-engine-id :md5))
  (println "Kul (MD5):" (map #(format "%02x" %) kul-md5))
  ;; Expected: 52 6f 5e ed 9f cc e2 6f 89 64 c2 93 07 87 d8 2b

  (def kul-sha (localize-key ku-sha test-engine-id :sha))
  (println "Kul (SHA):" (map #(format "%02x" %) kul-sha))
  ;; Expected: 66 95 fe bc 92 88 e3 62 82 23 5f c7 15 1f 12 84 97 b3 8f 3f

  ;; One-step localization
  (def kul-direct (password-to-localized-key test-password test-engine-id :md5))
  (println "Direct Kul:" (map #(format "%02x" %) kul-direct))
  (println "Keys match:" (Arrays/equals kul-md5 kul-direct))
  )
