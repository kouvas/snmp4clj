(ns kouvas.snmp4clj.v3.usm-test
  "Tests for SNMPv3 USM parameters encoding/decoding."
  (:require [clojure.test :refer :all]
            [kouvas.snmp4clj.v3.usm :as usm])
  (:import [java.util Arrays]))

;; ============================================================================
;; USM Parameters Creation Tests
;; ============================================================================

(deftest make-usm-parameters-test
  (testing "Create USM parameters with all fields"
    (let [engine-id (byte-array [0x80 0x00 0x1f 0x88 0x03])
          usm       (usm/make-usm-parameters engine-id 5 123456 "admin"
                                             (byte-array 12)
                                             (byte-array 0))]
      (is (= 5 (alength (:msgAuthoritativeEngineID usm))))
      (is (= 5 (:msgAuthoritativeEngineBoots usm)))
      (is (= 123456 (:msgAuthoritativeEngineTime usm)))
      (is (= "admin" (:msgUserName usm)))
      (is (= 12 (alength (:msgAuthenticationParameters usm))))
      (is (= 0 (alength (:msgPrivacyParameters usm))))))

  (testing "Create USM parameters with minimal fields"
    (let [engine-id (byte-array [0x80 0x00 0x00 0x00 0x01])
          usm       (usm/make-usm-parameters engine-id "user")]
      (is (= 5 (alength (:msgAuthoritativeEngineID usm))))
      (is (= 0 (:msgAuthoritativeEngineBoots usm)))
      (is (= 0 (:msgAuthoritativeEngineTime usm)))
      (is (= "user" (:msgUserName usm))))))

(deftest make-discovery-usm-parameters-test
  (testing "Create discovery USM parameters"
    (let [usm (usm/make-discovery-usm-parameters)]
      (is (zero? (alength (:msgAuthoritativeEngineID usm))) "Engine ID should be empty")
      (is (zero? (:msgAuthoritativeEngineBoots usm)))
      (is (zero? (:msgAuthoritativeEngineTime usm)))
      (is (= "" (:msgUserName usm)))
      (is (zero? (alength (:msgAuthenticationParameters usm))))
      (is (zero? (alength (:msgPrivacyParameters usm))))
      (is (true? (usm/discovery-request? usm))))))

;; ============================================================================
;; USM Parameters Encoding/Decoding Tests
;; ============================================================================

(deftest encode-decode-usm-parameters-test
  (testing "Round-trip encoding/decoding of USM parameters"
    (let [engine-id   (byte-array [0x80 0x00 0x1f 0x88 0x03 0x01 0x02 0x03 0x04])
          auth-params (byte-array (repeat 12 0xAB))
          usm         (usm/make-usm-parameters engine-id 10 999999 "testuser"
                                               auth-params
                                               (byte-array 0))
          encoded     (usm/encode-usm-parameters usm)
          decoded     (usm/decode-usm-parameters encoded)]

      (is (Arrays/equals (:msgAuthoritativeEngineID usm)
                         (:msgAuthoritativeEngineID decoded))
          "Engine ID should match")
      (is (= (:msgAuthoritativeEngineBoots usm)
             (:msgAuthoritativeEngineBoots decoded))
          "Engine boots should match")
      (is (= (:msgAuthoritativeEngineTime usm)
             (:msgAuthoritativeEngineTime decoded))
          "Engine time should match")
      (is (= (:msgUserName usm)
             (:msgUserName decoded))
          "Username should match")
      (is (Arrays/equals (:msgAuthenticationParameters usm)
                         (:msgAuthenticationParameters decoded))
          "Auth params should match")
      (is (Arrays/equals (:msgPrivacyParameters usm)
                         (:msgPrivacyParameters decoded))
          "Priv params should match"))))

(deftest encode-decode-discovery-test
  (testing "Encode/decode discovery USM parameters"
    (let [usm     (usm/make-discovery-usm-parameters)
          encoded (usm/encode-usm-parameters usm)
          decoded (usm/decode-usm-parameters encoded)]
      (is (zero? (alength (:msgAuthoritativeEngineID decoded))))
      (is (zero? (:msgAuthoritativeEngineBoots decoded)))
      (is (= "" (:msgUserName decoded)))
      (is (true? (usm/discovery-request? decoded))))))

;; ============================================================================
;; Validation Tests
;; ============================================================================

(deftest validate-usm-parameters-test
  (testing "Valid USM parameters pass validation"
    (let [usm (usm/make-usm-parameters
                (byte-array [0x80 0x00 0x00 0x00 0x01])
                5
                123456
                "admin")]
      (is (true? (usm/validate-usm-parameters! usm)))))

  (testing "Discovery parameters pass validation"
    (let [usm (usm/make-discovery-usm-parameters)]
      (is (true? (usm/validate-usm-parameters! usm)))))

  (testing "Engine ID too short fails validation"
    (let [usm (usm/make-usm-parameters
                (byte-array [0x80 0x00 0x00])  ; Only 3 bytes
                0 0 "user")]
      (is (thrown-with-msg?
            clojure.lang.ExceptionInfo
            #"Invalid engine ID length"
            (usm/validate-usm-parameters! usm)))))

  (testing "Engine ID too long fails validation"
    (let [usm (usm/make-usm-parameters
                (byte-array (repeat 33 0x00))  ; 33 bytes
                0 0 "user")]
      (is (thrown-with-msg?
            clojure.lang.ExceptionInfo
            #"Invalid engine ID length"
            (usm/validate-usm-parameters! usm)))))

  (testing "Username too long fails validation"
    (let [long-username (apply str (repeat 33 "x"))
          usm           (usm/make-usm-parameters
                          (byte-array 5)
                          0 0 long-username)]
      (is (thrown-with-msg?
            clojure.lang.ExceptionInfo
            #"Username too long"
            (usm/validate-usm-parameters! usm)))))

  (testing "Invalid auth params length fails validation"
    (let [usm (assoc (usm/make-usm-parameters
                       (byte-array 5)
                       0 0 "user")
                :msgAuthenticationParameters (byte-array 10))]  ; Should be 0 or 12
      (is (thrown-with-msg?
            clojure.lang.ExceptionInfo
            #"Invalid authentication parameters length"
            (usm/validate-usm-parameters! usm)))))

  (testing "Negative boots fails validation"
    (let [usm (usm/make-usm-parameters
                (byte-array 5)
                -1  ; Negative boots
                0 "user")]
      (is (thrown-with-msg?
            clojure.lang.ExceptionInfo
            #"Engine boots cannot be negative"
            (usm/validate-usm-parameters! usm)))))

  (testing "Negative time fails validation"
    (let [usm (usm/make-usm-parameters
                (byte-array 5)
                0
                -1  ; Negative time
                "user")]
      (is (thrown-with-msg?
            clojure.lang.ExceptionInfo
            #"Engine time cannot be negative"
            (usm/validate-usm-parameters! usm))))))

;; ============================================================================
;; Utility Function Tests
;; ============================================================================

(deftest update-auth-params-test
  (testing "Update authentication parameters"
    (let [usm         (usm/make-usm-parameters (byte-array 5) "user")
          new-params  (byte-array (repeat 12 0xFF))
          updated     (usm/update-auth-params usm new-params)]
      (is (Arrays/equals new-params (:msgAuthenticationParameters updated))))))

(deftest zero-auth-params-test
  (testing "Zero out authentication parameters"
    (let [usm    (usm/make-usm-parameters (byte-array 5) "user"
                                          (byte-array (repeat 12 0xFF))
                                          (byte-array 0))
          zeroed (usm/zero-auth-params usm)]
      (is (= 12 (alength (:msgAuthenticationParameters zeroed))))
      (is (every? zero? (:msgAuthenticationParameters zeroed))))))

(deftest usm-parameters-to-map-test
  (testing "Convert USM parameters to map"
    (let [engine-id (byte-array [0x80 0x00 0x1f 0x88])
          usm       (usm/make-usm-parameters engine-id 5 123456 "admin")
          m         (usm/usm-parameters->map usm)]
      (is (= [0x80 0x00 0x1f 0x88] (:engine-id m)))
      (is (= 5 (:engine-boots m)))
      (is (= 123456 (:engine-time m)))
      (is (= "admin" (:username m)))
      (is (= 12 (:auth-params-len m)))
      (is (= 0 (:priv-params-len m))))))

;; ============================================================================
;; Edge Cases
;; ============================================================================

(deftest edge-cases-test
  (testing "Minimum valid engine ID (5 bytes)"
    (let [usm (usm/make-usm-parameters (byte-array 5) "user")]
      (is (true? (usm/validate-usm-parameters! usm)))))

  (testing "Maximum valid engine ID (32 bytes)"
    (let [usm (usm/make-usm-parameters (byte-array 32) "user")]
      (is (true? (usm/validate-usm-parameters! usm)))))

  (testing "Empty username"
    (let [usm (usm/make-usm-parameters (byte-array 5) "")]
      (is (true? (usm/validate-usm-parameters! usm)))))

  (testing "Maximum username length (32 chars)"
    (let [usm (usm/make-usm-parameters (byte-array 5) (apply str (repeat 32 "x")))]
      (is (true? (usm/validate-usm-parameters! usm)))))

  (testing "Large engine boots and time values"
    (let [usm (usm/make-usm-parameters (byte-array 5)
                                       Integer/MAX_VALUE
                                       Integer/MAX_VALUE
                                       "user")]
      (is (true? (usm/validate-usm-parameters! usm))))))
