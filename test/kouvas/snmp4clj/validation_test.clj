(ns kouvas.snmp4clj.validation-test
  "Tests for SNMP version-specific validation."
  (:require [clojure.test :refer :all]
            [kouvas.snmp4clj.validation :as valid]))

;; ============================================================================
;; Operation Validation Tests
;; ============================================================================

(deftest operation-supported-test
  (testing "SNMPv1 operation support"
    (is (true? (valid/operation-supported? :snmp/v1 :get)))
    (is (true? (valid/operation-supported? :snmp/v1 :get-next)))
    (is (true? (valid/operation-supported? :snmp/v1 :set)))
    (is (true? (valid/operation-supported? :snmp/v1 :trap-v1)))
    (is (false? (valid/operation-supported? :snmp/v1 :get-bulk))
        "GET-BULK not supported in v1")
    (is (false? (valid/operation-supported? :snmp/v1 :inform))
        "INFORM not supported in v1")
    (is (false? (valid/operation-supported? :snmp/v1 :trap))
        "v2c TRAP format not supported in v1"))

  (testing "SNMPv2c operation support"
    (is (true? (valid/operation-supported? :snmp/v2c :get)))
    (is (true? (valid/operation-supported? :snmp/v2c :get-next)))
    (is (true? (valid/operation-supported? :snmp/v2c :set)))
    (is (true? (valid/operation-supported? :snmp/v2c :get-bulk))
        "GET-BULK supported in v2c")
    (is (true? (valid/operation-supported? :snmp/v2c :inform)))
    (is (true? (valid/operation-supported? :snmp/v2c :trap)))
    (is (true? (valid/operation-supported? :snmp/v2c :response)))
    (is (false? (valid/operation-supported? :snmp/v2c :trap-v1))
        "v1 TRAP format not used in v2c")))

(deftest validate-operation-test
  (testing "Valid operations don't throw"
    (is (nil? (valid/validate-operation! :snmp/v1 :get)))
    (is (nil? (valid/validate-operation! :snmp/v2c :get-bulk))))

  (testing "Invalid operations throw with details"
    (let [ex (try
               (valid/validate-operation! :snmp/v1 :get-bulk)
               (catch clojure.lang.ExceptionInfo e e))]
      (is (some? ex))
      (is (= "Operation not supported for SNMP version" (.getMessage ex)))
      (let [data (ex-data ex)]
        (is (= :snmp/v1 (:version data)))
        (is (= :get-bulk (:operation data)))
        (is (contains? (:supported data) :get))
        (is (not (contains? (:supported data) :get-bulk)))))))

;; ============================================================================
;; Error Code Validation Tests
;; ============================================================================

(deftest error-code-supported-test
  (testing "SNMPv1 error codes (0-5)"
    (is (true? (valid/error-code-supported? :snmp/v1 0)) "noError")
    (is (true? (valid/error-code-supported? :snmp/v1 1)) "tooBig")
    (is (true? (valid/error-code-supported? :snmp/v1 2)) "noSuchName")
    (is (true? (valid/error-code-supported? :snmp/v1 3)) "badValue")
    (is (true? (valid/error-code-supported? :snmp/v1 4)) "readOnly")
    (is (true? (valid/error-code-supported? :snmp/v1 5)) "genErr")
    (is (false? (valid/error-code-supported? :snmp/v1 6)) "noAccess - v2c only")
    (is (false? (valid/error-code-supported? :snmp/v1 18)) "inconsistentName - v2c only"))

  (testing "SNMPv2c error codes (0-18)"
    (is (true? (valid/error-code-supported? :snmp/v2c 0)))
    (is (true? (valid/error-code-supported? :snmp/v2c 5)))
    (is (true? (valid/error-code-supported? :snmp/v2c 6)) "noAccess - v2c+")
    (is (true? (valid/error-code-supported? :snmp/v2c 18)) "inconsistentName")
    (is (false? (valid/error-code-supported? :snmp/v2c 19)) "Invalid error code")))

(deftest validate-error-code-test
  (testing "Valid error codes don't throw"
    (is (nil? (valid/validate-error-code! :snmp/v1 0)))
    (is (nil? (valid/validate-error-code! :snmp/v1 5)))
    (is (nil? (valid/validate-error-code! :snmp/v2c 18))))

  (testing "Invalid error codes throw with details"
    (let [ex (try
               (valid/validate-error-code! :snmp/v1 6)
               (catch clojure.lang.ExceptionInfo e e))]
      (is (some? ex))
      (is (= "Error code not supported for SNMP version" (.getMessage ex)))
      (let [data (ex-data ex)]
        (is (= :snmp/v1 (:version data)))
        (is (= 6 (:error-code data)))
        (is (contains? (:supported data) 0))
        (is (not (contains? (:supported data) 6)))))))

;; ============================================================================
;; Data Type Validation Tests
;; ============================================================================

(deftest type-supported-test
  (testing "Common types supported in both v1 and v2c"
    (doseq [version [:snmp/v1 :snmp/v2c]
            type [:ber/integer :ber/octet-string :ber/null :ber/oid
                  :ber/ip-address :ber/counter32 :ber/gauge32
                  :ber/timeticks :ber/opaque]]
      (is (true? (valid/type-supported? version type))
          (str type " should be supported in " version))))

  (testing "SNMPv1 does not support Counter64"
    (is (false? (valid/type-supported? :snmp/v1 :ber/counter64))
        "Counter64 not supported in v1")
    (is (true? (valid/type-supported? :snmp/v2c :ber/counter64))
        "Counter64 supported in v2c"))

  (testing "SNMPv1 does not support exception values"
    (is (false? (valid/type-supported? :snmp/v1 :ber/no-such-object)))
    (is (false? (valid/type-supported? :snmp/v1 :ber/no-such-instance)))
    (is (false? (valid/type-supported? :snmp/v1 :ber/end-of-mib-view)))
    (is (true? (valid/type-supported? :snmp/v2c :ber/no-such-object)))
    (is (true? (valid/type-supported? :snmp/v2c :ber/no-such-instance)))
    (is (true? (valid/type-supported? :snmp/v2c :ber/end-of-mib-view)))))

(deftest validate-type-test
  (testing "Valid types don't throw"
    (is (nil? (valid/validate-type! :snmp/v1 :ber/integer)))
    (is (nil? (valid/validate-type! :snmp/v2c :ber/counter64))))

  (testing "Invalid types throw with details"
    (let [ex (try
               (valid/validate-type! :snmp/v1 :ber/counter64)
               (catch clojure.lang.ExceptionInfo e e))]
      (is (some? ex))
      (is (= "Data type not supported for SNMP version" (.getMessage ex)))
      (let [data (ex-data ex)]
        (is (= :snmp/v1 (:version data)))
        (is (= :ber/counter64 (:type data)))
        (is (contains? (:supported data) :ber/counter32))
        (is (not (contains? (:supported data) :ber/counter64)))))))

;; ============================================================================
;; Version Validation Tests
;; ============================================================================

(deftest version-supported-test
  (testing "Supported versions"
    (is (true? (valid/version-supported? :snmp/v1)))
    (is (true? (valid/version-supported? :snmp/v2c))))

  (testing "Unsupported versions"
    (is (false? (valid/version-supported? :snmp/v3))
        "v3 not yet implemented")
    (is (false? (valid/version-supported? :invalid)))))

(deftest validate-version-test
  (testing "Valid versions don't throw"
    (is (nil? (valid/validate-version! :snmp/v1)))
    (is (nil? (valid/validate-version! :snmp/v2c))))

  (testing "Invalid versions throw with details"
    (let [ex (try
               (valid/validate-version! :snmp/v3)
               (catch clojure.lang.ExceptionInfo e e))]
      (is (some? ex))
      (is (= "SNMP version not supported" (.getMessage ex)))
      (let [data (ex-data ex)]
        (is (= :snmp/v3 (:version data)))
        (is (contains? (:supported data) :snmp/v1))
        (is (contains? (:supported data) :snmp/v2c))
        (is (not (contains? (:supported data) :snmp/v3)))))))

;; ============================================================================
;; Integration Tests
;; ============================================================================

(deftest version-operation-combinations-test
  (testing "Valid v1 operations"
    (doseq [op [:get :get-next :set]]
      (is (nil? (valid/validate-operation! :snmp/v1 op))
          (str op " should be valid for v1"))))

  (testing "Invalid v1 operations"
    (doseq [op [:get-bulk :inform :trap :report]]
      (is (thrown? clojure.lang.ExceptionInfo
                   (valid/validate-operation! :snmp/v1 op))
          (str op " should be invalid for v1"))))

  (testing "All v2c operations are valid"
    (doseq [op [:get :get-next :set :get-bulk :inform :trap :response :report]]
      (is (nil? (valid/validate-operation! :snmp/v2c op))
          (str op " should be valid for v2c")))))
