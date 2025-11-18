(ns kouvas.snmp4clj.v3.message-test
  "Tests for SNMPv3 message structure encoding/decoding."
  (:require [clojure.test :refer :all]
            [kouvas.snmp4clj.v3.message :as msg]
            [kouvas.snmp4clj.v3.usm :as usm]
            [kouvas.snmp4clj.v3.crypto :as crypto]
            [kouvas.snmp4clj.pdu :as pdu]
            [kouvas.snmp4clj.smi.oid :as oid]
            [kouvas.snmp4clj.smi.variable-binding :as vb])
  (:import [java.util Arrays]))

;; ============================================================================
;; Message Flags Tests
;; ============================================================================

(deftest make-msg-flags-test
  (testing "noAuthNoPriv flags"
    (is (= 0x00 (msg/make-msg-flags :no-auth-no-priv false)))
    (is (= 0x04 (msg/make-msg-flags :no-auth-no-priv true)) "Reportable bit set"))

  (testing "authNoPriv flags"
    (is (= 0x01 (msg/make-msg-flags :auth-no-priv false)))
    (is (= 0x05 (msg/make-msg-flags :auth-no-priv true)) "Auth + reportable"))

  (testing "authPriv flags"
    (is (= 0x03 (msg/make-msg-flags :auth-priv false)))
    (is (= 0x07 (msg/make-msg-flags :auth-priv true)) "Auth + priv + reportable")))

(deftest parse-msg-flags-test
  (testing "Parse noAuthNoPriv flags"
    (let [parsed (msg/parse-msg-flags 0x00)]
      (is (= :no-auth-no-priv (:security-level parsed)))
      (is (false? (:reportable? parsed)))))

  (testing "Parse authNoPriv flags"
    (let [parsed (msg/parse-msg-flags 0x01)]
      (is (= :auth-no-priv (:security-level parsed)))
      (is (false? (:reportable? parsed)))))

  (testing "Parse authPriv flags"
    (let [parsed (msg/parse-msg-flags 0x03)]
      (is (= :auth-priv (:security-level parsed)))
      (is (false? (:reportable? parsed)))))

  (testing "Parse with reportable bit"
    (let [parsed (msg/parse-msg-flags 0x05)]  ; auth + reportable
      (is (= :auth-no-priv (:security-level parsed)))
      (is (true? (:reportable? parsed))))))

;; ============================================================================
;; HeaderData Tests
;; ============================================================================

(deftest make-header-data-test
  (testing "Create HeaderData with minimal args"
    (let [header (msg/make-header-data 123456 :auth-no-priv false)]
      (is (= 123456 (:msgID header)))
      (is (= 65507 (:msgMaxSize header)))  ; Default
      (is (= 0x01 (:msgFlags header)))     ; authNoPriv
      (is (= 3 (:msgSecurityModel header))))) ; USM

  (testing "Create HeaderData with all args"
    (let [header (msg/make-header-data 999 32768 :auth-priv true 3)]
      (is (= 999 (:msgID header)))
      (is (= 32768 (:msgMaxSize header)))
      (is (= 0x07 (:msgFlags header)))  ; auth + priv + reportable
      (is (= 3 (:msgSecurityModel header))))))

(deftest encode-decode-header-data-test
  (testing "Round-trip encoding/decoding of HeaderData"
    (let [header  (msg/make-header-data 54321 :auth-no-priv true)
          encoded (msg/encode-header-data header)
          tlv     (kouvas.snmp4clj.ber/bytes->tlv-structure encoded)
          decoded (msg/decode-header-data tlv)]
      (is (= (:msgID header) (:msgID decoded)))
      (is (= (:msgMaxSize header) (:msgMaxSize decoded)))
      (is (= (:msgFlags header) (:msgFlags decoded)))
      (is (= (:msgSecurityModel header) (:msgSecurityModel decoded))))))

;; ============================================================================
;; ScopedPDU Tests
;; ============================================================================

(deftest make-scoped-pdu-test
  (testing "Create ScopedPDU with minimal args"
    (let [test-pdu (pdu/make-pdu
                     (vb/make-variable-bindings
                       [(oid/make-oid "1.3.6.1.2.1.1.1.0")]))
          scoped   (msg/make-scoped-pdu test-pdu)]
      (is (zero? (alength (:contextEngineID scoped))) "Default empty context engine ID")
      (is (= "" (:contextName scoped)) "Default empty context name")
      (is (some? (:data scoped)))))

  (testing "Create ScopedPDU with context"
    (let [test-pdu     (pdu/make-pdu
                         (vb/make-variable-bindings
                           [(oid/make-oid "1.3.6.1.2.1.1.1.0")]))
          context-id   (byte-array [0x80 0x00 0x00 0x00 0x01])
          scoped       (msg/make-scoped-pdu context-id "mycontext" test-pdu)]
      (is (= 5 (alength (:contextEngineID scoped))))
      (is (= "mycontext" (:contextName scoped))))))

(deftest encode-decode-scoped-pdu-test
  (testing "Round-trip encoding/decoding of ScopedPDU"
    (let [test-pdu (pdu/make-pdu
                     (vb/make-variable-bindings
                       [(oid/make-oid "1.3.6.1.2.1.1.1.0")]))
          scoped   (msg/make-scoped-pdu test-pdu)
          encoded  (msg/encode-scoped-pdu scoped)
          tlv      (kouvas.snmp4clj.ber/bytes->tlv-structure encoded)
          decoded  (msg/decode-scoped-pdu tlv)]
      (is (Arrays/equals (:contextEngineID scoped) (:contextEngineID decoded)))
      (is (= (:contextName scoped) (:contextName decoded)))
      ;; PDU comparison is complex, just verify it's present
      (is (some? (:data decoded))))))

;; ============================================================================
;; Complete Message Tests
;; ============================================================================

(deftest make-snmpv3-message-test
  (testing "Create complete SNMPv3 message"
    (let [test-pdu   (pdu/make-pdu
                       (vb/make-variable-bindings
                         [(oid/make-oid "1.3.6.1.2.1.1.1.0")]))
          header     (msg/make-header-data 12345 :auth-no-priv false)
          usm-params (usm/make-usm-parameters
                       (byte-array [0x80 0x00 0x00 0x00 0x01])
                       "admin")
          scoped-pdu (msg/make-scoped-pdu test-pdu)
          message    (msg/make-snmpv3-message header usm-params scoped-pdu)]
      (is (= 3 (:msgVersion message)))
      (is (some? (:msgGlobalData message)))
      (is (some? (:msgSecurityParameters message)))
      (is (some? (:msgData message))))))

(deftest encode-decode-message-no-auth-test
  (testing "Encode/decode message without authentication"
    (let [test-pdu   (pdu/make-pdu
                       (vb/make-variable-bindings
                         [(oid/make-oid "1.3.6.1.2.1.1.1.0")]))
          header     (msg/make-header-data 99999 :no-auth-no-priv true)
          usm-params (usm/make-discovery-usm-parameters)
          scoped-pdu (msg/make-scoped-pdu test-pdu)
          message    (msg/make-snmpv3-message header usm-params scoped-pdu)
          encoded    (msg/encode-snmpv3-message message nil nil)
          decoded    (msg/decode-snmpv3-message encoded)]
      (is (= 3 (:msgVersion decoded)))
      (is (= 99999 (get-in decoded [:msgGlobalData :msgID])))
      (is (zero? (alength (get-in decoded [:msgSecurityParameters :msgAuthoritativeEngineID])))))))

(deftest encode-message-with-auth-test
  (testing "Encode message with HMAC authentication"
    (let [test-pdu      (pdu/make-pdu
                          (vb/make-variable-bindings
                            [(oid/make-oid "1.3.6.1.2.1.1.1.0")]))
          engine-id     (byte-array [0x80 0x00 0x1f 0x88 0x03 0x01 0x02 0x03 0x04])
          header        (msg/make-header-data 55555 :auth-no-priv false)
          usm-params    (usm/make-usm-parameters engine-id 5 123456 "admin")
          scoped-pdu    (msg/make-scoped-pdu test-pdu)
          message       (msg/make-snmpv3-message header usm-params scoped-pdu)

          ;; Generate localized key
          localized-key (crypto/password-to-localized-key "secret123" engine-id :md5)

          ;; Encode with authentication
          encoded       (msg/encode-snmpv3-message message localized-key :md5)]

      (is (vector? encoded))
      (is (pos? (count encoded)))

      ;; Decode and verify structure
      (let [decoded (msg/decode-snmpv3-message encoded)]
        (is (= 3 (:msgVersion decoded)))
        (is (= 55555 (get-in decoded [:msgGlobalData :msgID])))

        ;; Verify HMAC was inserted (not all zeros)
        (let [auth-params (get-in decoded [:msgSecurityParameters :msgAuthenticationParameters])]
          (is (= 12 (alength auth-params)))
          (is (not (every? zero? auth-params)) "HMAC should not be all zeros"))))))

;; ============================================================================
;; Discovery Message Tests
;; ============================================================================

(deftest make-discovery-message-test
  (testing "Create discovery message"
    (let [test-pdu (pdu/make-pdu
                     (vb/make-variable-bindings
                       [(oid/make-oid "1.3.6.1.2.1.1.1.0")]))
          message  (msg/make-discovery-message test-pdu)]
      (is (= 3 (:msgVersion message)))
      (is (true? (usm/discovery-request? (:msgSecurityParameters message))))

      ;; Check flags are correct for discovery (noAuth + reportable)
      (let [flags  (get-in message [:msgGlobalData :msgFlags])
            parsed (msg/parse-msg-flags flags)]
        (is (= :no-auth-no-priv (:security-level parsed)))
        (is (true? (:reportable? parsed)))))))

(deftest encode-decode-discovery-message-test
  (testing "Encode/decode discovery message"
    (let [test-pdu (pdu/make-pdu
                     (vb/make-variable-bindings
                       [(oid/make-oid "1.3.6.1.2.1.1.1.0")]))
          message  (msg/make-discovery-message test-pdu)
          encoded  (msg/encode-snmpv3-message message nil nil)
          decoded  (msg/decode-snmpv3-message encoded)]
      (is (= 3 (:msgVersion decoded)))
      (is (true? (usm/discovery-request? (:msgSecurityParameters decoded)))))))

;; ============================================================================
;; Authenticated Message Tests
;; ============================================================================

(deftest make-authenticated-message-test
  (testing "Create authenticated message"
    (let [test-pdu  (pdu/make-pdu
                      (vb/make-variable-bindings
                        [(oid/make-oid "1.3.6.1.2.1.1.1.0")]))
          engine-id (byte-array [0x80 0x00 0x00 0x00 0x01])
          message   (msg/make-authenticated-message test-pdu engine-id 10 999999 "admin" false)]
      (is (= 3 (:msgVersion message)))
      (is (= "admin" (get-in message [:msgSecurityParameters :msgUserName])))
      (is (= 10 (get-in message [:msgSecurityParameters :msgAuthoritativeEngineBoots])))
      (is (= 999999 (get-in message [:msgSecurityParameters :msgAuthoritativeEngineTime])))

      ;; Check flags
      (let [flags  (get-in message [:msgGlobalData :msgFlags])
            parsed (msg/parse-msg-flags flags)]
        (is (= :auth-no-priv (:security-level parsed)))
        (is (false? (:reportable? parsed)))))))

;; ============================================================================
;; Utility Function Tests
;; ============================================================================

(deftest generate-msg-id-test
  (testing "Generate message IDs"
    (let [id1 (msg/generate-msg-id)
          id2 (msg/generate-msg-id)]
      (is (integer? id1))
      (is (>= id1 0))
      (is (< id1 Integer/MAX_VALUE))
      ;; IDs should be different (statistically)
      (is (not= id1 id2)))))

;; ============================================================================
;; Integration Tests
;; ============================================================================

(deftest full-authenticated-message-flow-test
  (testing "Complete authenticated message flow"
    (let [;; Setup
          test-pdu      (pdu/make-pdu
                          (vb/make-variable-bindings
                            [(oid/make-oid "1.3.6.1.2.1.1.1.0")
                             (oid/make-oid "1.3.6.1.2.1.1.3.0")]))
          engine-id     (byte-array [0x80 0x00 0x1f 0x88 0x03 0x01 0x02 0x03 0x04])
          password      "mySecretPassword123"
          username      "testuser"

          ;; Create message
          message       (msg/make-authenticated-message test-pdu engine-id 15 555555 username false)

          ;; Generate key and encode
          localized-key (crypto/password-to-localized-key password engine-id :sha)
          encoded       (msg/encode-snmpv3-message message localized-key :sha)

          ;; Decode
          decoded       (msg/decode-snmpv3-message encoded)]

      ;; Verify decoded message
      (is (= 3 (:msgVersion decoded)))
      (is (= username (get-in decoded [:msgSecurityParameters :msgUserName])))
      (is (= 15 (get-in decoded [:msgSecurityParameters :msgAuthoritativeEngineBoots])))

      ;; Verify HMAC is present
      (let [auth-params (get-in decoded [:msgSecurityParameters :msgAuthenticationParameters])]
        (is (= 12 (alength auth-params)))
        (is (not (every? zero? auth-params)))))))
