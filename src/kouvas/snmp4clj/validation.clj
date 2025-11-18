(ns kouvas.snmp4clj.validation
  "SNMP version-specific validation for operations, types, and error codes.")

;; ============================================================================
;; Version-specific Operation Support
;; ============================================================================

(def ^:private v1-operations
  "Operations supported in SNMPv1"
  #{:get :get-next :set :trap-v1})

(def ^:private v2c-operations
  "Operations supported in SNMPv2c (superset of v1)"
  #{:get :get-next :set :get-bulk :inform :trap :response :report})

(def ^:private v3-operations
  "Operations supported in SNMPv3 (same as v2c)"
  v2c-operations)

(defn operation-supported?
  "Check if an operation is supported for the given SNMP version."
  [version operation]
  (let [supported (case version
                    :snmp/v1  v1-operations
                    :snmp/v2c v2c-operations
                    :snmp/v3  v3-operations
                    #{})]
    (contains? supported operation)))

(defn validate-operation!
  "Validates that the operation is supported for the given SNMP version.
  Throws ex-info if not supported."
  [version operation]
  (when-not (operation-supported? version operation)
    (throw (ex-info "Operation not supported for SNMP version"
                    {:version   version
                     :operation operation
                     :supported (case version
                                  :snmp/v1  v1-operations
                                  :snmp/v2c v2c-operations
                                  :snmp/v3  v3-operations
                                  #{})}))))

;; ============================================================================
;; Version-specific Error Code Support
;; ============================================================================

(def ^:private v1-error-codes
  "Error codes supported in SNMPv1 (RFC 1157)"
  #{0   ; noError
    1   ; tooBig
    2   ; noSuchName
    3   ; badValue
    4   ; readOnly
    5}) ; genErr

(def ^:private v2c-error-codes
  "Error codes supported in SNMPv2c (RFC 1905)"
  #{0   ; noError
    1   ; tooBig
    2   ; noSuchName
    3   ; badValue
    4   ; readOnly
    5   ; genErr
    6   ; noAccess
    7   ; wrongType
    8   ; wrongLength
    9   ; wrongEncoding
    10  ; wrongValue
    11  ; noCreation
    12  ; inconsistentValue
    13  ; resourceUnavailable
    14  ; commitFailed
    15  ; undoFailed
    16  ; authorizationError
    17  ; notWritable
    18}) ; inconsistentName

(def ^:private v3-error-codes
  "Error codes supported in SNMPv3 (same as v2c)"
  v2c-error-codes)

(defn error-code-supported?
  "Check if an error code is supported for the given SNMP version."
  [version error-code]
  (let [supported (case version
                    :snmp/v1  v1-error-codes
                    :snmp/v2c v2c-error-codes
                    :snmp/v3  v3-error-codes
                    #{})]
    (contains? supported error-code)))

(defn validate-error-code!
  "Validates that the error code is supported for the given SNMP version.
  Throws ex-info if not supported."
  [version error-code]
  (when-not (error-code-supported? version error-code)
    (throw (ex-info "Error code not supported for SNMP version"
                    {:version    version
                     :error-code error-code
                     :supported  (case version
                                   :snmp/v1  v1-error-codes
                                   :snmp/v2c v2c-error-codes
                                   :snmp/v3  v3-error-codes
                                   #{})}))))

;; ============================================================================
;; Version-specific Data Type Support
;; ============================================================================

(def ^:private v1-types
  "SMI types supported in SNMPv1 (RFC 1155)"
  #{:ber/integer
    :ber/octet-string
    :ber/null
    :ber/oid
    :ber/ip-address
    :ber/counter32    ; Called just "Counter" in v1
    :ber/gauge32      ; Called just "Gauge" in v1
    :ber/timeticks
    :ber/opaque})

(def ^:private v2c-types
  "SMI types supported in SNMPv2c (RFC 1902/1903) - superset of v1"
  (into v1-types
        #{:ber/counter64         ; New in v2c
          :ber/bit-str           ; Defined but deprecated
          :ber/no-such-object    ; Exception values
          :ber/no-such-instance
          :ber/end-of-mib-view}))

(def ^:private v3-types
  "SMI types supported in SNMPv3 (same as v2c)"
  v2c-types)

(defn type-supported?
  "Check if a BER type is supported for the given SNMP version."
  [version ber-type]
  (let [supported (case version
                    :snmp/v1  v1-types
                    :snmp/v2c v2c-types
                    :snmp/v3  v3-types
                    #{})]
    (contains? supported ber-type)))

(defn validate-type!
  "Validates that the BER type is supported for the given SNMP version.
  Throws ex-info if not supported."
  [version ber-type]
  (when-not (type-supported? version ber-type)
    (throw (ex-info "Data type not supported for SNMP version"
                    {:version   version
                     :type      ber-type
                     :supported (case version
                                  :snmp/v1  v1-types
                                  :snmp/v2c v2c-types
                                  :snmp/v3  v3-types
                                  #{})}))))

;; ============================================================================
;; Version Validation
;; ============================================================================

(def ^:private supported-versions
  #{:snmp/v1 :snmp/v2c :snmp/v3})

(defn version-supported?
  "Check if an SNMP version is supported."
  [version]
  (contains? supported-versions version))

(defn validate-version!
  "Validates that the SNMP version is supported.
  Throws ex-info if not supported."
  [version]
  (when-not (version-supported? version)
    (throw (ex-info "SNMP version not supported"
                    {:version   version
                     :supported supported-versions}))))

(comment
  ;; Test v1 operations
  (operation-supported? :snmp/v1 :get)        ; => true
  (operation-supported? :snmp/v1 :get-bulk)   ; => false
  (operation-supported? :snmp/v2c :get-bulk)  ; => true

  ;; Test error codes
  (error-code-supported? :snmp/v1 5)   ; => true (genErr)
  (error-code-supported? :snmp/v1 6)   ; => false (noAccess - v2c only)
  (error-code-supported? :snmp/v2c 6)  ; => true

  ;; Test types
  (type-supported? :snmp/v1 :ber/counter32)  ; => true
  (type-supported? :snmp/v1 :ber/counter64)  ; => false (v2c+ only)
  (type-supported? :snmp/v2c :ber/counter64) ; => true

  ;; Validation throws
  (try
    (validate-operation! :snmp/v1 :get-bulk)
    (catch Exception e
      (ex-data e)))
  ; => {:version :snmp/v1, :operation :get-bulk, :supported #{:get :get-next :set :trap-v1}}
  )
