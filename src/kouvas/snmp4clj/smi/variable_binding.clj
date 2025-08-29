"
The term variable refers to an instance of a managed object. A
variable binding, or VarBind, refers to the pairing of the name of a
variable to the variable's value more specifically it's an association
of an object instance identifier and it's value(variable) which value can be of
various SMI types.

Requests that value part of a VarBind can be of NULL SMI data type:
GetRequest-PDU - Yes, uses NULL
GetNextRequest-PDU - Yes, uses NULL
GetBulkRequest-PDU (SNMPv2) - Yes, uses NULL
SetRequest-PDU - No, contains actual values to set
GetResponse-PDU - No, contains actual values (or exceptions)
Trap/Notification PDUs - No, contain actual values

Defined:
SMIv1 - https://www.rfc-editor.org/rfc/rfc1157.html#section-4.1.1
SMIv2 - https://www.rfc-editor.org/rfc/rfc3416.html#section-3
SMIv2(snmp v3) - https://www.rfc-editor.org/rfc/rfc3418.html
"
(ns kouvas.snmp4clj.smi.variable-binding
  (:require [kouvas.snmp4clj.ber :as ber]
            [kouvas.snmp4clj.variable :as p]
            [kouvas.snmp4clj.smi.null :as null]
            [kouvas.snmp4clj.smi.oid :as oid]))

(def ^:const ^:private null-oid (oid/make-oid))
(def ^:const ^:private null-variable (null/make-null))

;; one varbind contains only one pair of oid and it's value(an snmp/smi variable) which,
;; for all get requests is Null
(defrecord VariableBinding [oid variable type])

(defn- var-bind-payload-length
  [this]
  (let [oid-length (ber/ber-length (:oid this))
        var-length (ber/ber-length (:variable this))]
    (+ oid-length var-length)))

(defn var-bind-ber-length
  [this]
  (let [ber-payload-length (ber/ber-payload-length this)
        space              (ber/ber-length-of-length ber-payload-length)]
    (+ ber-payload-length space 1)))

(extend VariableBinding
  ber/BERSerializable
  {:encode-ber         (fn [this] (ber/encode-var-bind this))
   :ber-payload-length (fn [this] (var-bind-payload-length this))
   :ber-length         (fn [this] (var-bind-ber-length this))})

(defn make-variable-binding
  ([]
   (make-variable-binding null-oid))
  ([oid]
   (make-variable-binding oid null-variable))
  ([oid variable]
   (->VariableBinding oid variable :ber/sequence)))

(defn make-variable-bindings
  [oids]
  ;; encode each oid
  (mapv make-variable-binding oids))


(comment
  (def vv
    (make-variable-binding (oid/make-oid [1 3 6 1 2 1 1 1 0])))
  vv
  (ber/encode-sequence (ber/encode-var-bind vv))
  (p/encode-ber vv)
  (p/ber-length vv)

  (vec
    (byte-array
      (conj (conj '() 0x02 0xa0) 0x82))
    )
  )