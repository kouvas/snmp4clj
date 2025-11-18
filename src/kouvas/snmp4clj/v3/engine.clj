(ns kouvas.snmp4clj.v3.engine
  "SNMPv3 Engine ID discovery and management.

  Implements RFC 3414 engine ID discovery and caching."
  (:require [kouvas.snmp4clj.v3.message :as msg]
            [kouvas.snmp4clj.v3.usm :as usm]
            [kouvas.snmp4clj.v3.crypto :as crypto]
            [kouvas.snmp4clj.pdu :as pdu]
            [kouvas.snmp4clj.smi.oid :as oid]
            [kouvas.snmp4clj.smi.variable-binding :as vb])
  (:import [java.time Instant]))

;; ============================================================================
;; Engine State Management
;; ============================================================================

(defrecord EngineState
  [engine-id          ; byte-array - authoritative engine ID
   engine-boots       ; int - engine boots counter
   engine-time        ; int - engine time at last update
   last-updated       ; Instant - when this was last updated
   username           ; string - associated username
   auth-protocol      ; keyword - :md5 or :sha
   localized-key])    ; byte-array - localized authentication key

(defn make-engine-state
  "Create engine state record.

  Parameters:
  - engine-id: Authoritative engine ID bytes
  - engine-boots: Engine boots counter
  - engine-time: Engine time in seconds
  - username: SNMP v3 username
  - auth-protocol: Authentication protocol (:md5 or :sha)
  - localized-key: Localized authentication key bytes

  Returns: EngineState record"
  [engine-id engine-boots engine-time username auth-protocol localized-key]
  (->EngineState
    (if (bytes? engine-id) engine-id (byte-array engine-id))
    (int engine-boots)
    (int engine-time)
    (Instant/now)
    username
    auth-protocol
    (if (bytes? localized-key) localized-key (byte-array localized-key))))

(defn update-engine-time
  "Update engine state with new boots and time.

  Returns: Updated EngineState"
  [engine-state boots time]
  (assoc engine-state
    :engine-boots (int boots)
    :engine-time (int time)
    :last-updated (Instant/now)))

(defn get-current-engine-time
  "Get current engine time, adjusting for elapsed time since last update.

  Estimates current engine time based on when it was last updated.

  Returns: Estimated current engine time (integer)"
  [engine-state]
  (let [last-time (:engine-time engine-state)
        last-instant (:last-updated engine-state)
        now (Instant/now)
        elapsed-seconds (.getEpochSecond (.between java.time.temporal.ChronoUnit/SECONDS last-instant now))]
    (+ last-time elapsed-seconds)))

;; ============================================================================
;; Engine Cache (Simple Atom-based)
;; ============================================================================

(def ^:private engine-cache
  "Cache of known engines by host:port"
  (atom {}))

(defn cache-key
  "Generate cache key from host and port.

  Returns: String key"
  [host port]
  (str host ":" port))

(defn get-cached-engine
  "Retrieve cached engine state for host:port.

  Returns: EngineState or nil if not cached"
  [host port]
  (get @engine-cache (cache-key host port)))

(defn cache-engine!
  "Cache engine state for host:port."
  [host port engine-state]
  (swap! engine-cache assoc (cache-key host port) engine-state)
  engine-state)

(defn clear-engine-cache!
  "Clear all cached engine states."
  []
  (reset! engine-cache {}))

(defn remove-cached-engine!
  "Remove cached engine state for specific host:port."
  [host port]
  (swap! engine-cache dissoc (cache-key host port)))

;; ============================================================================
;; Discovery Protocol
;; ============================================================================

(def usmStatsUnknownEngineIDs-oid "1.3.6.1.6.3.15.1.1.4.0")

(defn parse-discovery-response
  "Parse engine discovery response to extract engine ID.

  Discovery responses are Report PDUs containing usmStatsUnknownEngineIDs.
  The engine ID is in the msgSecurityParameters.

  Parameters:
  - response-message: Decoded SNMPv3Message record

  Returns: byte-array engine ID, or nil if not a valid discovery response"
  [response-message]
  (when (= 3 (:msgVersion response-message))
    (let [usm-params (:msgSecurityParameters response-message)
          engine-id (:msgAuthoritativeEngineID usm-params)]
      ;; Discovery responses have non-empty engine ID
      (when (pos? (alength engine-id))
        engine-id))))

(defn create-discovery-request
  "Create engine ID discovery request.

  Discovery requests use:
  - Empty engine ID
  - Empty username
  - Empty auth parameters
  - Reportable flag set
  - Minimal PDU (GET request for sysDescr)

  Returns: Encoded message bytes (vector)"
  []
  (let [;; Create minimal PDU for discovery (GET sysDescr)
        test-pdu (pdu/make-pdu
                   (vb/make-variable-bindings
                     [(oid/make-oid "1.3.6.1.2.1.1.1.0")]))

        ;; Create discovery message
        discovery-msg (msg/make-discovery-message test-pdu)

        ;; Encode (no authentication for discovery)
        encoded (msg/encode-snmpv3-message discovery-msg nil nil)]
    encoded))

(defn discover-engine-id
  "Perform engine ID discovery for a host.

  Sends discovery request and extracts engine ID from response.

  Parameters:
  - send-fn: Function to send request bytes and receive response bytes
            (fn [request-bytes] -> response-bytes)

  Returns: byte-array engine ID, or nil if discovery failed"
  [send-fn]
  (let [request (create-discovery-request)
        response-bytes (send-fn request)]
    (when response-bytes
      (let [response-msg (msg/decode-snmpv3-message response-bytes)
            engine-id (parse-discovery-response response-msg)]
        engine-id))))

;; ============================================================================
;; Time Synchronization Protocol
;; ============================================================================

(def usmStatsNotInTimeWindows-oid "1.3.6.1.6.3.15.1.1.2.0")

(defn parse-time-sync-response
  "Parse time synchronization response to extract boots and time.

  Time sync responses contain engine boots and time in USM parameters.

  Parameters:
  - response-message: Decoded SNMPv3Message record

  Returns: {:boots int, :time int} or nil if invalid"
  [response-message]
  (when (= 3 (:msgVersion response-message))
    (let [usm-params (:msgSecurityParameters response-message)
          boots (:msgAuthoritativeEngineBoots usm-params)
          time (:msgAuthoritativeEngineTime usm-params)]
      ;; Time sync responses have non-zero boots or time
      (when (or (pos? boots) (pos? time))
        {:boots boots
         :time time}))))

(defn create-time-sync-request
  "Create time synchronization request.

  Parameters:
  - engine-id: Discovered engine ID bytes
  - username: SNMP v3 username
  - password: Authentication password
  - auth-protocol: :md5 or :sha

  Returns: Encoded message bytes (vector)"
  [engine-id username password auth-protocol]
  (let [;; Generate localized key
        localized-key (crypto/password-to-localized-key password engine-id auth-protocol)

        ;; Create minimal PDU
        test-pdu (pdu/make-pdu
                   (vb/make-variable-bindings
                     [(oid/make-oid "1.3.6.1.2.1.1.1.0")]))

        ;; Create authenticated message with boots=0, time=0, reportable=true
        header (msg/make-header-data (msg/generate-msg-id) :auth-no-priv true)
        usm-params (usm/make-usm-parameters engine-id 0 0 username)
        scoped-pdu (msg/make-scoped-pdu test-pdu)
        message (msg/make-snmpv3-message header usm-params scoped-pdu)

        ;; Encode with authentication
        encoded (msg/encode-snmpv3-message message localized-key auth-protocol)]
    encoded))

(defn synchronize-time
  "Perform time synchronization for an engine.

  Sends authenticated request with boots=0, time=0 to get current values.

  Parameters:
  - engine-id: Discovered engine ID bytes
  - username: SNMP v3 username
  - password: Authentication password
  - auth-protocol: :md5 or :sha
  - send-fn: Function to send request and receive response

  Returns: {:boots int, :time int} or nil if sync failed"
  [engine-id username password auth-protocol send-fn]
  (let [request (create-time-sync-request engine-id username password auth-protocol)
        response-bytes (send-fn request)]
    (when response-bytes
      (let [response-msg (msg/decode-snmpv3-message response-bytes)
            time-info (parse-time-sync-response response-msg)]
        time-info))))

;; ============================================================================
;; High-Level Discovery + Sync
;; ============================================================================

(defn discover-and-sync
  "Perform full discovery and time synchronization.

  This is the high-level function that:
  1. Discovers engine ID (if needed)
  2. Synchronizes time
  3. Generates and caches localized key
  4. Returns complete engine state

  Parameters:
  - host: Target host
  - port: Target port
  - username: SNMP v3 username
  - password: Authentication password
  - auth-protocol: :md5 or :sha
  - send-fn: Function to send request and receive response
  - force-discovery?: If true, ignore cache and re-discover

  Returns: EngineState record or nil if failed"
  ([host port username password auth-protocol send-fn]
   (discover-and-sync host port username password auth-protocol send-fn false))
  ([host port username password auth-protocol send-fn force-discovery?]
   (let [;; Check cache first (unless forcing rediscovery)
         cached (when-not force-discovery?
                  (get-cached-engine host port))

         ;; If cached and same credentials, use it
         use-cached? (and cached
                          (= username (:username cached))
                          (= auth-protocol (:auth-protocol cached)))]

     (if use-cached?
       cached

       ;; Otherwise, discover and sync
       (let [;; Step 1: Discover engine ID
             engine-id (discover-engine-id send-fn)]

         (when engine-id
           ;; Step 2: Synchronize time
           (let [time-info (synchronize-time engine-id username password auth-protocol send-fn)]

             (when time-info
               ;; Step 3: Generate localized key
               (let [localized-key (crypto/password-to-localized-key password engine-id auth-protocol)

                     ;; Step 4: Create and cache engine state
                     engine-state (make-engine-state
                                    engine-id
                                    (:boots time-info)
                                    (:time time-info)
                                    username
                                    auth-protocol
                                    localized-key)]

                 ;; Cache it
                 (cache-engine! host port engine-state)
                 engine-state)))))))))

(comment
  ;; Example usage:
  (require '[kouvas.snmp4clj.net :as net])

  ;; Define send function for UDP
  (defn udp-send-recv [host port request-bytes]
    (net/send-snmp-request host port request-bytes 5000))

  ;; Discover and sync
  (def engine-state
    (discover-and-sync
      "192.168.1.1"
      161
      "myuser"
      "mypassword"
      :md5
      (partial udp-send-recv "192.168.1.1" 161)))

  ;; Check cached state
  (get-cached-engine "192.168.1.1" 161)

  ;; Clear cache
  (clear-engine-cache!)
  )
