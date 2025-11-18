(ns kouvas.snmp4clj.v3.crypto-test
  "Tests for SNMPv3 cryptographic operations using RFC 3414 test vectors."
  (:require [clojure.test :refer :all]
            [kouvas.snmp4clj.v3.crypto :as crypto])
  (:import [java.util Arrays]))

;; ============================================================================
;; RFC 3414 Appendix A Test Vectors
;; ============================================================================

(def rfc-test-password "maplesyrup")
(def rfc-test-engine-id
  (byte-array [0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
               0x00 0x00 0x00 0x02]))

;; Expected Ku (user key) from RFC 3414 Appendix A.3.1
(def expected-ku-md5
  (byte-array [(unchecked-byte 0x9f) (unchecked-byte 0xaf) 0x32 (unchecked-byte 0x83)
               (unchecked-byte 0x88) 0x4e (unchecked-byte 0x92) (unchecked-byte 0x83)
               0x4e (unchecked-byte 0xbc) (unchecked-byte 0x98) 0x47
               (unchecked-byte 0xd8) (unchecked-byte 0xed) (unchecked-byte 0xd9) 0x63]))

(def expected-ku-sha
  (byte-array [(unchecked-byte 0x9f) (unchecked-byte 0xb5) (unchecked-byte 0xcc) 0x03
               (unchecked-byte 0x81) 0x49 0x7b 0x37
               (unchecked-byte 0x93) 0x52 (unchecked-byte 0x89) 0x39
               (unchecked-byte 0xff) 0x78 (unchecked-byte 0x8d) 0x5d
               0x79 0x14 0x52 0x11]))

;; Expected Kul (localized key) from RFC 3414 Appendix A.3.2
(def expected-kul-md5
  (byte-array [0x52 0x6f 0x5e (unchecked-byte 0xed)
               (unchecked-byte 0x9f) (unchecked-byte 0xcc) (unchecked-byte 0xe2) 0x6f
               (unchecked-byte 0x89) 0x64 (unchecked-byte 0xc2) (unchecked-byte 0x93)
               0x07 (unchecked-byte 0x87) (unchecked-byte 0xd8) 0x2b]))

(def expected-kul-sha
  (byte-array [0x66 (unchecked-byte 0x95) (unchecked-byte 0xfe) (unchecked-byte 0xbc)
               (unchecked-byte 0x92) (unchecked-byte 0x88) (unchecked-byte 0xe3) 0x62
               (unchecked-byte 0x82) 0x23 0x5f (unchecked-byte 0xc7)
               0x15 0x1f 0x12 (unchecked-byte 0x84)
               (unchecked-byte 0x97) (unchecked-byte 0xb3) (unchecked-byte 0x8f) 0x3f]))

;; ============================================================================
;; Helper Functions
;; ============================================================================

(defn bytes-to-hex
  "Convert byte array to hex string for debugging"
  [bytes]
  (apply str (map #(format "%02x" (bit-and % 0xFF)) bytes)))

(defn assert-bytes-equal
  "Assert two byte arrays are equal with helpful error message"
  [expected actual msg]
  (when-not (Arrays/equals expected actual)
    (is false (str msg "\n"
                   "Expected: " (bytes-to-hex expected) "\n"
                   "Actual:   " (bytes-to-hex actual)))))

;; ============================================================================
;; Password-to-Key Tests (RFC 3414 Appendix A.3.1)
;; ============================================================================

(deftest password-to-key-md5-test
  (testing "Generate Ku using MD5 according to RFC 3414"
    (let [ku (crypto/password-to-key rfc-test-password :md5)]
      (is (= 16 (alength ku)) "MD5 Ku should be 16 bytes")
      (assert-bytes-equal expected-ku-md5 ku
                          "MD5 Ku should match RFC 3414 test vector"))))

(deftest password-to-key-sha-test
  (testing "Generate Ku using SHA-1 according to RFC 3414"
    (let [ku (crypto/password-to-key rfc-test-password :sha)]
      (is (= 20 (alength ku)) "SHA Ku should be 20 bytes")
      (assert-bytes-equal expected-ku-sha ku
                          "SHA Ku should match RFC 3414 test vector"))))

(deftest password-to-key-invalid-algorithm-test
  (testing "Invalid algorithm throws exception"
    (is (thrown-with-msg?
          clojure.lang.ExceptionInfo
          #"Unsupported hash algorithm"
          (crypto/password-to-key "password" :invalid)))))

;; ============================================================================
;; Key Localization Tests (RFC 3414 Appendix A.3.2)
;; ============================================================================

(deftest localize-key-md5-test
  (testing "Localize MD5 key with engine ID according to RFC 3414"
    (let [ku  (crypto/password-to-key rfc-test-password :md5)
          kul (crypto/localize-key ku rfc-test-engine-id :md5)]
      (is (= 16 (alength kul)) "MD5 Kul should be 16 bytes")
      (assert-bytes-equal expected-kul-md5 kul
                          "MD5 Kul should match RFC 3414 test vector"))))

(deftest localize-key-sha-test
  (testing "Localize SHA-1 key with engine ID according to RFC 3414"
    (let [ku  (crypto/password-to-key rfc-test-password :sha)
          kul (crypto/localize-key ku rfc-test-engine-id :sha)]
      (is (= 20 (alength kul)) "SHA Kul should be 20 bytes")
      (assert-bytes-equal expected-kul-sha kul
                          "SHA Kul should match RFC 3414 test vector"))))

(deftest localize-key-invalid-algorithm-test
  (testing "Invalid algorithm throws exception"
    (let [ku (crypto/password-to-key "password" :md5)]
      (is (thrown-with-msg?
            clojure.lang.ExceptionInfo
            #"Unsupported hash algorithm"
            (crypto/localize-key ku (byte-array 12) :invalid))))))

;; ============================================================================
;; One-Step Localization Tests
;; ============================================================================

(deftest password-to-localized-key-md5-test
  (testing "One-step password to localized key (MD5)"
    (let [kul (crypto/password-to-localized-key rfc-test-password
                                                 rfc-test-engine-id
                                                 :md5)]
      (is (= 16 (alength kul)))
      (assert-bytes-equal expected-kul-md5 kul
                          "One-step MD5 Kul should match RFC test vector"))))

(deftest password-to-localized-key-sha-test
  (testing "One-step password to localized key (SHA)"
    (let [kul (crypto/password-to-localized-key rfc-test-password
                                                 rfc-test-engine-id
                                                 :sha)]
      (is (= 20 (alength kul)))
      (assert-bytes-equal expected-kul-sha kul
                          "One-step SHA Kul should match RFC test vector"))))

;; ============================================================================
;; HMAC Tests
;; ============================================================================

(deftest calculate-hmac-md5-test
  (testing "Calculate HMAC-MD5 authentication parameters"
    (let [message       (byte-array (range 100))  ; Test message
          localized-key expected-kul-md5
          hmac          (crypto/calculate-hmac message localized-key :md5)]

      (is (= 12 (alength hmac)) "HMAC output should be 12 bytes")
      (is (every? #(instance? Byte %) (seq hmac)) "Should return byte array"))))

(deftest calculate-hmac-sha-test
  (testing "Calculate HMAC-SHA1 authentication parameters"
    (let [message       (byte-array (range 100))
          localized-key expected-kul-sha
          hmac          (crypto/calculate-hmac message localized-key :sha)]

      (is (= 12 (alength hmac)) "HMAC output should be 12 bytes"))))

(deftest verify-hmac-test
  (testing "Verify HMAC matches calculated value"
    (let [message       (byte-array (range 100))
          localized-key expected-kul-md5
          hmac          (crypto/calculate-hmac message localized-key :md5)]

      (is (true? (crypto/verify-hmac message hmac localized-key :md5))
          "HMAC verification should succeed for matching HMAC")

      ;; Tamper with message
      (aset message 50 (byte 0xFF))
      (is (false? (crypto/verify-hmac message hmac localized-key :md5))
          "HMAC verification should fail for tampered message"))))

(deftest calculate-hmac-invalid-algorithm-test
  (testing "Invalid algorithm throws exception"
    (is (thrown-with-msg?
          clojure.lang.ExceptionInfo
          #"Unsupported HMAC algorithm"
          (crypto/calculate-hmac (byte-array 10) (byte-array 16) :invalid)))))

;; ============================================================================
;; Utility Function Tests
;; ============================================================================

(deftest zero-auth-params-test
  (testing "Generate zero authentication parameters"
    (let [zeros (crypto/zero-auth-params)]
      (is (= 12 (alength zeros)) "Should be 12 bytes")
      (is (every? zero? zeros) "All bytes should be zero"))))

(deftest key-length-test
  (testing "Get expected key lengths"
    (is (= 16 (crypto/key-length :md5)) "MD5 key is 16 bytes")
    (is (= 20 (crypto/key-length :sha)) "SHA key is 20 bytes")
    (is (thrown-with-msg?
          clojure.lang.ExceptionInfo
          #"Unsupported algorithm"
          (crypto/key-length :invalid)))))

;; ============================================================================
;; Integration Test
;; ============================================================================

(deftest full-authentication-flow-test
  (testing "Complete authentication flow from password to HMAC verification"
    (let [password    "secret123"
          engine-id   (byte-array [0x80 0x00 0x1f 0x88 0x03 0x01 0x02 0x03 0x04])
          message     (byte-array (concat [0x30 0x50]  ; SEQUENCE
                                         (range 78)))   ; Dummy content

          ;; Generate localized key
          kul         (crypto/password-to-localized-key password engine-id :md5)

          ;; Calculate HMAC
          hmac        (crypto/calculate-hmac message kul :md5)

          ;; Verify HMAC
          verified?   (crypto/verify-hmac message hmac kul :md5)]

      (is (= 16 (alength kul)) "Localized key should be 16 bytes")
      (is (= 12 (alength hmac)) "HMAC should be 12 bytes")
      (is (true? verified?) "HMAC verification should succeed"))))

;; ============================================================================
;; Edge Cases
;; ============================================================================

(deftest empty-password-test
  (testing "Empty password generates valid key"
    (let [ku (crypto/password-to-key "" :md5)]
      (is (= 16 (alength ku)))
      (is (not (every? zero? ku)) "Key should not be all zeros"))))

(deftest long-password-test
  (testing "Very long password (> 1MB when repeated) works"
    (let [long-password (apply str (repeat 1000 "x"))
          ku            (crypto/password-to-key long-password :md5)]
      (is (= 16 (alength ku)))
      (is (not (every? zero? ku))))))

(deftest short-engine-id-test
  (testing "Short engine ID (minimum 5 bytes)"
    (let [short-engine (byte-array [0x80 0x00 0x00 0x00 0x01])
          ku           (crypto/password-to-key "password" :md5)
          kul          (crypto/localize-key ku short-engine :md5)]
      (is (= 16 (alength kul))))))

(deftest long-engine-id-test
  (testing "Long engine ID (maximum 32 bytes)"
    (let [long-engine (byte-array (range 32))
          ku          (crypto/password-to-key "password" :md5)
          kul         (crypto/localize-key ku long-engine :md5)]
      (is (= 16 (alength kul))))))
