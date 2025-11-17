(ns examples.snmp-v1-v2c-comparison
  "Demonstrates the differences between SNMPv1 and SNMPv2c usage."
  (:require [kouvas.snmp4clj.snmp :as snmp]))

;; ============================================================================
;; Basic Usage - v1 and v2c
;; ============================================================================

(comment
  ;; SNMPv2c request (default)
  (def v2c-result
    (snmp/snmp-request {:version   :snmp/v2c
                        :host      "localhost"
                        :port      5161
                        :community "public"
                        :oids      ["1.3.6.1.2.1.1.1.0"  ; sysDescr
                                    "1.3.6.1.2.1.1.3.0"  ; sysUpTime
                                    "1.3.6.1.2.1.1.7.0"]})) ; sysServices

  ;; Parse the response
  (snmp/->response v2c-result)
  ;;=> {"1.3.6.1.2.1.1.1.0" "Snmpd test container..."
  ;;    "1.3.6.1.2.1.1.3.0" "5 days, 3:24:15.67"
  ;;    "1.3.6.1.2.1.1.7.0" 88}


  ;; SNMPv1 request (just change :version)
  (def v1-result
    (snmp/snmp-request {:version   :snmp/v1
                        :host      "localhost"
                        :port      5161
                        :community "public"
                        :oids      ["1.3.6.1.2.1.1.1.0"
                                    "1.3.6.1.2.1.1.3.0"
                                    "1.3.6.1.2.1.1.7.0"]}))

  (snmp/->response v1-result)
  ;;=> Same result as v2c for these OIDs


  ;; ============================================================================
  ;; Demonstrating v1 Limitations
  ;; ============================================================================

  ;; GET-BULK is v2c+ only - this will throw an exception
  (try
    (snmp/snmp-request {:version   :snmp/v1
                        :operation :get-bulk
                        :host      "localhost"
                        :community "public"
                        :oids      ["1.3.6.1.2.1.1"]})
    (catch clojure.lang.ExceptionInfo e
      (println "Error:" (.getMessage e))
      (println "Details:" (ex-data e))))
  ;;=> Error: Operation not supported for SNMP version
  ;;   Details: {:version :snmp/v1, :operation :get-bulk, :supported #{:get :get-next :set :trap-v1}}


  ;; GET-BULK works fine with v2c
  (def bulk-result
    (snmp/snmp-request {:version   :snmp/v2c
                        :operation :get-bulk
                        :host      "localhost"
                        :port      5161
                        :community "public"
                        :oids      ["1.3.6.1.2.1.1"]}))


  ;; ============================================================================
  ;; Supported Operations by Version
  ;; ============================================================================

  ;; SNMPv1 supports:
  ;; - :get
  ;; - :get-next
  ;; - :set
  ;; - :trap-v1

  ;; SNMPv2c adds:
  ;; - :get-bulk (efficient bulk retrieval)
  ;; - :inform (acknowledged notifications)
  ;; - :trap (improved trap format)
  ;; - :response
  ;; - :report


  ;; ============================================================================
  ;; When to Use v1 vs v2c
  ;; ============================================================================

  ;; Use SNMPv1 when:
  ;; - Working with legacy/older devices that only support v1
  ;; - Required by network policy
  ;; - Device explicitly doesn't support v2c

  ;; Use SNMPv2c when:
  ;; - Working with modern devices (most support v2c)
  ;; - Need GET-BULK for efficient table walking
  ;; - Need 64-bit counters (Counter64)
  ;; - Want more detailed error messages


  ;; ============================================================================
  ;; Data Type Differences
  ;; ============================================================================

  ;; SNMPv1 does NOT support Counter64
  ;; If you query a Counter64 OID with v1, the agent might:
  ;; - Return an error
  ;; - Truncate to 32 bits
  ;; - Return a different value

  ;; Example: High-bandwidth interface counters
  ;; ifHCInOctets (64-bit) works in v2c but not v1
  (def v2c-64bit
    (snmp/snmp-request {:version   :snmp/v2c
                        :host      "device-ip"
                        :community "public"
                        :oids      ["1.3.6.1.2.1.31.1.1.1.6.1"]})) ; ifHCInOctets
  )
