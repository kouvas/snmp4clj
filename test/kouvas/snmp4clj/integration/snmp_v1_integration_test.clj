(ns kouvas.snmp4clj.integration.snmp-v1-integration-test
  "Integration tests for SNMPv1 against a real SNMP agent.

  Prerequisites:
  - Docker and docker-compose installed
  - Run: cd snmpd-container && docker-compose up -d
  - Agent should be listening on localhost:5161"
  (:require [clojure.test :refer :all]
            [kouvas.snmp4clj.snmp :as snmp]))

(def ^:dynamic *snmpd-available* false)

(defn check-snmpd-available
  "Check if snmpd test container is available on localhost:5161"
  []
  (try
    (let [result (snmp/snmp-request {:version   :snmp/v2c
                                     :host      "localhost"
                                     :port      5161
                                     :community "public"
                                     :timeout   1000
                                     :oids      ["1.3.6.1.2.1.1.1.0"]})]
      (some? result))
    (catch Exception _ false)))

(use-fixtures :once
  (fn [f]
    (binding [*snmpd-available* (check-snmpd-available)]
      (when-not *snmpd-available*
        (println "\nWARNING: snmpd container not available on localhost:5161")
        (println "Skipping integration tests. To run:")
        (println "  cd snmpd-container && docker-compose up -d\n"))
      (f))))

(deftest ^:integration snmpv1-get-request-test
  (when *snmpd-available*
    (testing "SNMPv1 GET request for sysDescr"
      (let [result (snmp/snmp-request {:version   :snmp/v1
                                       :host      "localhost"
                                       :port      5161
                                       :community "public"
                                       :oids      ["1.3.6.1.2.1.1.1.0"]})]
        (is (some? result) "Should receive a response")
        (is (vector? result) "Should return a vector of bytes")
        (is (pos? (count result)) "Response should not be empty")

        (let [parsed (snmp/->response result)]
          (is (map? parsed) "Should parse to a map")
          (is (contains? parsed "1.3.6.1.2.1.1.1.0") "Should contain sysDescr OID")
          (is (string? (get parsed "1.3.6.1.2.1.1.1.0")) "sysDescr should be a string"))))))

(deftest ^:integration snmpv1-multiple-oids-test
  (when *snmpd-available*
    (testing "SNMPv1 GET request for multiple OIDs"
      (let [oids ["1.3.6.1.2.1.1.1.0"   ; sysDescr (string)
                  "1.3.6.1.2.1.1.3.0"   ; sysUpTime (timeticks)
                  "1.3.6.1.2.1.1.7.0"]  ; sysServices (integer)
            result (snmp/snmp-request {:version   :snmp/v1
                                       :host      "localhost"
                                       :port      5161
                                       :community "public"
                                       :oids      oids})
            parsed (snmp/->response result)]

        (is (= 3 (count parsed)) "Should return all 3 OIDs")
        (is (string? (get parsed "1.3.6.1.2.1.1.1.0")) "sysDescr is string")
        (is (string? (get parsed "1.3.6.1.2.1.1.3.0")) "sysUpTime is formatted string")
        (is (number? (get parsed "1.3.6.1.2.1.1.7.0")) "sysServices is integer")))))

(deftest ^:integration snmpv1-vs-v2c-compatibility-test
  (when *snmpd-available*
    (testing "SNMPv1 and v2c return same results for compatible OIDs"
      (let [oids ["1.3.6.1.2.1.1.1.0"
                  "1.3.6.1.2.1.1.7.0"]
            v1-result (snmp/->response
                        (snmp/snmp-request {:version   :snmp/v1
                                            :host      "localhost"
                                            :port      5161
                                            :community "public"
                                            :oids      oids}))
            v2c-result (snmp/->response
                         (snmp/snmp-request {:version   :snmp/v2c
                                             :host      "localhost"
                                             :port      5161
                                             :community "public"
                                             :oids      oids}))]

        (is (= v1-result v2c-result)
            "v1 and v2c should return identical results for common OIDs")))))

(deftest ^:integration snmpv1-get-bulk-rejected-test
  (testing "SNMPv1 rejects GET-BULK operation"
    (is (thrown-with-msg?
          clojure.lang.ExceptionInfo
          #"Operation not supported"
          (snmp/snmp-request {:version   :snmp/v1
                              :operation :get-bulk
                              :host      "localhost"
                              :port      5161
                              :community "public"
                              :oids      ["1.3.6.1.2.1.1"]})))))

(deftest ^:integration snmpv1-invalid-community-test
  (when *snmpd-available*
    (testing "SNMPv1 with invalid community returns nil (timeout/error)"
      (let [result (snmp/snmp-request {:version   :snmp/v1
                                       :host      "localhost"
                                       :port      5161
                                       :community "invalid-community"
                                       :timeout   2000
                                       :oids      ["1.3.6.1.2.1.1.1.0"]})]
        (is (nil? result) "Should return nil for invalid community")))))

(comment
  ;; Run integration tests manually:
  (run-tests 'kouvas.snmp4clj.integration.snmp-v1-integration-test)

  ;; Run just v1 vs v2c comparison:
  (snmpv1-vs-v2c-compatibility-test)
  )
