(ns kouvas.snmp4clj.v3.engine-test
  "Tests for SNMPv3 engine discovery and management."
  (:require [clojure.test :refer :all]
            [kouvas.snmp4clj.v3.engine :as engine]
            [kouvas.snmp4clj.v3.message :as msg]
            [kouvas.snmp4clj.v3.usm :as usm]
            [kouvas.snmp4clj.v3.crypto :as crypto]
            [kouvas.snmp4clj.pdu :as pdu]
            [kouvas.snmp4clj.smi.oid :as oid]
            [kouvas.snmp4clj.smi.variable-binding :as vb])
  (:import [java.util Arrays]
           [java.time Instant]))

;; ============================================================================
;; Engine State Tests
;; ============================================================================

(deftest make-engine-state-test
  (testing "Create engine state"
    (let [engine-id (byte-array [0x80 0x00 0x1f 0x88 0x03])
          key (byte-array 16)
          state (engine/make-engine-state engine-id 5 123456 "admin" :md5 key)]
      (is (= 5 (alength (:engine-id state))))
      (is (= 5 (:engine-boots state)))
      (is (= 123456 (:engine-time state)))
      (is (= "admin" (:username state)))
      (is (= :md5 (:auth-protocol state)))
      (is (= 16 (alength (:localized-key state))))
      (is (instance? Instant (:last-updated state))))))

(deftest update-engine-time-test
  (testing "Update engine time"
    (let [state (engine/make-engine-state (byte-array 5) 5 100 "user" :md5 (byte-array 16))
          updated (engine/update-engine-time state 6 200)]
      (is (= 6 (:engine-boots updated)))
      (is (= 200 (:engine-time updated)))
      (is (instance? Instant (:last-updated updated))))))

(deftest get-current-engine-time-test
  (testing "Get current engine time (immediate)"
    (let [state (engine/make-engine-state (byte-array 5) 5 1000 "user" :md5 (byte-array 16))
          current (engine/get-current-engine-time state)]
      ;; Should be approximately the same (within a second)
      (is (>= current 1000))
      (is (<= current 1002))))

  (testing "Get current engine time (after delay)"
    (let [state (engine/make-engine-state (byte-array 5) 5 1000 "user" :md5 (byte-array 16))]
      ;; Sleep 2 seconds
      (Thread/sleep 2000)
      (let [current (engine/get-current-engine-time state)]
        ;; Should be approximately 1002 (1000 + 2 seconds)
        (is (>= current 1001))
        (is (<= current 1003))))))

;; ============================================================================
;; Engine Cache Tests
;; ============================================================================

(deftest cache-engine-test
  (testing "Cache and retrieve engine state"
    (engine/clear-engine-cache!)
    (let [state (engine/make-engine-state (byte-array 5) 5 100 "user" :md5 (byte-array 16))]
      (engine/cache-engine! "localhost" 161 state)
      (let [cached (engine/get-cached-engine "localhost" 161)]
        (is (some? cached))
        (is (= 5 (:engine-boots cached)))
        (is (= "user" (:username cached)))))))

(deftest cache-key-test
  (testing "Cache key generation"
    (is (= "localhost:161" (engine/cache-key "localhost" 161)))
    (is (= "192.168.1.1:5161" (engine/cache-key "192.168.1.1" 5161)))))

(deftest clear-cache-test
  (testing "Clear engine cache"
    (engine/clear-engine-cache!)
    (let [state (engine/make-engine-state (byte-array 5) 5 100 "user" :md5 (byte-array 16))]
      (engine/cache-engine! "host1" 161 state)
      (engine/cache-engine! "host2" 161 state)
      (is (some? (engine/get-cached-engine "host1" 161)))
      (is (some? (engine/get-cached-engine "host2" 161)))

      (engine/clear-engine-cache!)
      (is (nil? (engine/get-cached-engine "host1" 161)))
      (is (nil? (engine/get-cached-engine "host2" 161))))))

(deftest remove-cached-engine-test
  (testing "Remove specific cached engine"
    (engine/clear-engine-cache!)
    (let [state (engine/make-engine-state (byte-array 5) 5 100 "user" :md5 (byte-array 16))]
      (engine/cache-engine! "host1" 161 state)
      (engine/cache-engine! "host2" 161 state)

      (engine/remove-cached-engine! "host1" 161)
      (is (nil? (engine/get-cached-engine "host1" 161)))
      (is (some? (engine/get-cached-engine "host2" 161))))))

;; ============================================================================
;; Discovery Request Tests
;; ============================================================================

(deftest create-discovery-request-test
  (testing "Create discovery request"
    (let [encoded (engine/create-discovery-request)
          decoded (msg/decode-snmpv3-message encoded)]
      (is (= 3 (:msgVersion decoded)))

      ;; Check USM parameters are empty for discovery
      (let [usm-params (:msgSecurityParameters decoded)]
        (is (zero? (alength (:msgAuthoritativeEngineID usm-params))) "Engine ID should be empty")
        (is (= "" (:msgUserName usm-params)) "Username should be empty")
        (is (zero? (alength (:msgAuthenticationParameters usm-params))) "Auth params should be empty"))

      ;; Check reportable flag is set
      (let [flags (get-in decoded [:msgGlobalData :msgFlags])
            parsed (msg/parse-msg-flags flags)]
        (is (true? (:reportable? parsed)) "Reportable flag should be set")
        (is (= :no-auth-no-priv (:security-level parsed)))))))

(deftest parse-discovery-response-test
  (testing "Parse valid discovery response"
    (let [engine-id (byte-array [0x80 0x00 0x1f 0x88 0x03 0x01 0x02 0x03 0x04])
          ;; Create mock discovery response
          header (msg/make-header-data 12345 :no-auth-no-priv false)
          usm-params (usm/make-usm-parameters engine-id 0 0 "")
          test-pdu (pdu/make-pdu
                     (vb/make-variable-bindings
                       [(oid/make-oid "1.3.6.1.2.1.1.1.0")]))
          scoped-pdu (msg/make-scoped-pdu test-pdu)
          response-msg (msg/make-snmpv3-message header usm-params scoped-pdu)

          extracted-id (engine/parse-discovery-response response-msg)]

      (is (some? extracted-id))
      (is (Arrays/equals engine-id extracted-id))))

  (testing "Parse response with empty engine ID"
    (let [;; Discovery request (empty engine ID) shouldn't parse as response
          header (msg/make-header-data 12345 :no-auth-no-priv false)
          usm-params (usm/make-discovery-usm-parameters)
          test-pdu (pdu/make-pdu (vb/make-variable-bindings [(oid/make-oid "1.3.6.1.2.1.1.1.0")]))
          scoped-pdu (msg/make-scoped-pdu test-pdu)
          request-msg (msg/make-snmpv3-message header usm-params scoped-pdu)

          extracted-id (engine/parse-discovery-response request-msg)]

      (is (nil? extracted-id) "Should not extract engine ID from empty discovery request"))))

;; ============================================================================
;; Time Sync Tests
;; ============================================================================

(deftest parse-time-sync-response-test
  (testing "Parse valid time sync response"
    (let [engine-id (byte-array [0x80 0x00 0x1f 0x88 0x03])
          header (msg/make-header-data 12345 :auth-no-priv false)
          usm-params (usm/make-usm-parameters engine-id 10 999999 "admin")
          test-pdu (pdu/make-pdu (vb/make-variable-bindings [(oid/make-oid "1.3.6.1.2.1.1.1.0")]))
          scoped-pdu (msg/make-scoped-pdu test-pdu)
          response-msg (msg/make-snmpv3-message header usm-params scoped-pdu)

          time-info (engine/parse-time-sync-response response-msg)]

      (is (some? time-info))
      (is (= 10 (:boots time-info)))
      (is (= 999999 (:time time-info)))))

  (testing "Parse response with zero boots and time"
    (let [engine-id (byte-array 5)
          header (msg/make-header-data 12345 :no-auth-no-priv false)
          usm-params (usm/make-usm-parameters engine-id 0 0 "")
          test-pdu (pdu/make-pdu (vb/make-variable-bindings [(oid/make-oid "1.3.6.1.2.1.1.1.0")]))
          scoped-pdu (msg/make-scoped-pdu test-pdu)
          response-msg (msg/make-snmpv3-message header usm-params scoped-pdu)

          time-info (engine/parse-time-sync-response response-msg)]

      (is (nil? time-info) "Should return nil for zero boots and time"))))

(deftest create-time-sync-request-test
  (testing "Create time sync request"
    (let [engine-id (byte-array [0x80 0x00 0x1f 0x88 0x03])
          password "testpass"
          encoded (engine/create-time-sync-request engine-id "admin" password :md5)
          decoded (msg/decode-snmpv3-message encoded)]

      (is (= 3 (:msgVersion decoded)))

      ;; Check USM parameters
      (let [usm-params (:msgSecurityParameters decoded)]
        (is (Arrays/equals engine-id (:msgAuthoritativeEngineID usm-params)))
        (is (= "admin" (:msgUserName usm-params)))
        (is (= 0 (:msgAuthoritativeEngineBoots usm-params)) "Boots should be 0 for sync")
        (is (= 0 (:msgAuthoritativeEngineTime usm-params)) "Time should be 0 for sync")

        ;; Auth params should be present (12 bytes HMAC)
        (is (= 12 (alength (:msgAuthenticationParameters usm-params))))
        (is (not (every? zero? (:msgAuthenticationParameters usm-params)))
            "HMAC should not be all zeros"))

      ;; Check reportable flag
      (let [flags (get-in decoded [:msgGlobalData :msgFlags])
            parsed (msg/parse-msg-flags flags)]
        (is (true? (:reportable? parsed)))
        (is (= :auth-no-priv (:security-level parsed)))))))

;; ============================================================================
;; Integration Tests
;; ============================================================================

(deftest discover-engine-id-integration-test
  (testing "Discover engine ID with mock send function"
    (let [expected-engine-id (byte-array [0x80 0x00 0x1f 0x88 0x03 0x01 0x02 0x03 0x04])

          ;; Mock send function that returns a discovery response
          mock-send-fn (fn [request-bytes]
                         ;; Create discovery response
                         (let [header (msg/make-header-data 12345 :no-auth-no-priv false)
                               usm-params (usm/make-usm-parameters expected-engine-id 0 0 "")
                               test-pdu (pdu/make-pdu (vb/make-variable-bindings [(oid/make-oid engine/usmStatsUnknownEngineIDs-oid)]))
                               scoped-pdu (msg/make-scoped-pdu test-pdu)
                               response-msg (msg/make-snmpv3-message header usm-params scoped-pdu)]
                           (msg/encode-snmpv3-message response-msg nil nil)))

          discovered-id (engine/discover-engine-id mock-send-fn)]

      (is (some? discovered-id))
      (is (Arrays/equals expected-engine-id discovered-id)))))

(deftest synchronize-time-integration-test
  (testing "Synchronize time with mock send function"
    (let [engine-id (byte-array [0x80 0x00 0x1f 0x88 0x03])
          password "testpass"

          ;; Mock send function that returns time sync response
          mock-send-fn (fn [request-bytes]
                         (let [header (msg/make-header-data 12345 :auth-no-priv false)
                               usm-params (usm/make-usm-parameters engine-id 15 555555 "admin")
                               test-pdu (pdu/make-pdu (vb/make-variable-bindings [(oid/make-oid engine/usmStatsNotInTimeWindows-oid)]))
                               scoped-pdu (msg/make-scoped-pdu test-pdu)
                               response-msg (msg/make-snmpv3-message header usm-params scoped-pdu)]
                           (msg/encode-snmpv3-message response-msg nil nil)))

          time-info (engine/synchronize-time engine-id "admin" password :md5 mock-send-fn)]

      (is (some? time-info))
      (is (= 15 (:boots time-info)))
      (is (= 555555 (:time time-info))))))

(deftest discover-and-sync-integration-test
  (testing "Full discovery and sync with mock send function"
    (engine/clear-engine-cache!)
    (let [expected-engine-id (byte-array [0x80 0x00 0x1f 0x88 0x03 0x01 0x02])
          password "testpass"
          call-count (atom 0)

          ;; Mock send function that handles both discovery and time sync
          mock-send-fn (fn [request-bytes]
                         (swap! call-count inc)
                         (let [decoded (msg/decode-snmpv3-message request-bytes)
                               usm-params (:msgSecurityParameters decoded)
                               engine-id-len (alength (:msgAuthoritativeEngineID usm-params))]

                           ;; First call: discovery (empty engine ID)
                           (if (zero? engine-id-len)
                             ;; Return discovery response
                             (let [header (msg/make-header-data 12345 :no-auth-no-priv false)
                                   usm-params (usm/make-usm-parameters expected-engine-id 0 0 "")
                                   test-pdu (pdu/make-pdu (vb/make-variable-bindings [(oid/make-oid engine/usmStatsUnknownEngineIDs-oid)]))
                                   scoped-pdu (msg/make-scoped-pdu test-pdu)
                                   response-msg (msg/make-snmpv3-message header usm-params scoped-pdu)]
                               (msg/encode-snmpv3-message response-msg nil nil))

                             ;; Second call: time sync (has engine ID)
                             (let [header (msg/make-header-data 12345 :auth-no-priv false)
                                   usm-params (usm/make-usm-parameters expected-engine-id 10 888888 "admin")
                                   test-pdu (pdu/make-pdu (vb/make-variable-bindings [(oid/make-oid engine/usmStatsNotInTimeWindows-oid)]))
                                   scoped-pdu (msg/make-scoped-pdu test-pdu)
                                   response-msg (msg/make-snmpv3-message header usm-params scoped-pdu)]
                               (msg/encode-snmpv3-message response-msg nil nil)))))

          engine-state (engine/discover-and-sync "testhost" 161 "admin" password :md5 mock-send-fn)]

      (is (some? engine-state) "Should return engine state")
      (is (= 2 @call-count) "Should make 2 calls: discovery + time sync")
      (is (Arrays/equals expected-engine-id (:engine-id engine-state)))
      (is (= 10 (:engine-boots engine-state)))
      (is (= 888888 (:engine-time engine-state)))
      (is (= "admin" (:username engine-state)))
      (is (= :md5 (:auth-protocol engine-state)))
      (is (= 16 (alength (:localized-key engine-state))))

      ;; Verify it was cached
      (let [cached (engine/get-cached-engine "testhost" 161)]
        (is (some? cached))
        (is (Arrays/equals expected-engine-id (:engine-id cached)))))))

(deftest discover-and-sync-uses-cache-test
  (testing "discover-and-sync uses cached state when appropriate"
    (engine/clear-engine-cache!)
    (let [call-count (atom 0)
          mock-send-fn (fn [_] (swap! call-count inc) nil)

          ;; Pre-populate cache
          cached-state (engine/make-engine-state
                         (byte-array 5) 5 100 "admin" :md5 (byte-array 16))]
      (engine/cache-engine! "testhost" 161 cached-state)

      ;; Call with same credentials
      (let [result (engine/discover-and-sync "testhost" 161 "admin" "pass" :md5 mock-send-fn)]
        (is (some? result))
        (is (zero? @call-count) "Should not make any network calls when using cache")
        (is (= 5 (:engine-boots result)))))))

(deftest discover-and-sync-force-rediscovery-test
  (testing "discover-and-sync with force-discovery ignores cache"
    (engine/clear-engine-cache!)
    (let [expected-engine-id (byte-array [0x80 0x00 0x1f 0x88 0x03])
          call-count (atom 0)

          mock-send-fn (fn [request-bytes]
                         (swap! call-count inc)
                         (let [decoded (msg/decode-snmpv3-message request-bytes)
                               usm-params (:msgSecurityParameters decoded)
                               engine-id-len (alength (:msgAuthoritativeEngineID usm-params))]
                           (if (zero? engine-id-len)
                             ;; Discovery response
                             (let [header (msg/make-header-data 1 :no-auth-no-priv false)
                                   usm (usm/make-usm-parameters expected-engine-id 0 0 "")
                                   pdu (pdu/make-pdu (vb/make-variable-bindings [(oid/make-oid engine/usmStatsUnknownEngineIDs-oid)]))
                                   scoped (msg/make-scoped-pdu pdu)
                                   msg (msg/make-snmpv3-message header usm scoped)]
                               (msg/encode-snmpv3-message msg nil nil))
                             ;; Time sync response
                             (let [header (msg/make-header-data 1 :auth-no-priv false)
                                   usm (usm/make-usm-parameters expected-engine-id 20 999999 "admin")
                                   pdu (pdu/make-pdu (vb/make-variable-bindings [(oid/make-oid engine/usmStatsNotInTimeWindows-oid)]))
                                   scoped (msg/make-scoped-pdu pdu)
                                   msg (msg/make-snmpv3-message header usm scoped)]
                               (msg/encode-snmpv3-message msg nil nil)))))

          ;; Pre-populate cache with old data
          old-state (engine/make-engine-state (byte-array 5) 1 50 "admin" :md5 (byte-array 16))]
      (engine/cache-engine! "testhost" 161 old-state)

      ;; Force rediscovery
      (let [result (engine/discover-and-sync "testhost" 161 "admin" "pass" :md5 mock-send-fn true)]
        (is (some? result))
        (is (= 2 @call-count) "Should make network calls despite cache")
        (is (= 20 (:engine-boots result)) "Should have new boots, not cached value")
        (is (= 999999 (:engine-time result)))))))
