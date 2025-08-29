(ns kouvas.snmp4clj.pdu
  (:require [kouvas.snmp4clj.ber :as ber]
            [kouvas.snmp4clj.variable :as p]
            [kouvas.snmp4clj.smi.integer32 :as i32]
            [kouvas.snmp4clj.smi.oid :as oid]
            [kouvas.snmp4clj.smi.variable-binding :as vb]))

(def ^:const max-size-request-pdu 65535)
(def ^:const min-pdu-length 484)


(defrecord PDU [variable-bindings type request-id error-status error-index])

(extend PDU
  p/Variable
  p/default-variable-behaviour

  ber/BERSerializable
  {:encode-ber (fn [this] (ber/encode-pdu this))}
  )

(defn- request-id
  []
  (rand-int (+ (- Integer/MAX_VALUE 2) 1)))

(defn make-pdu
  "variable-bindings: a vector of OIDs
  type: the PDU type
  request-id: a :ber/integer type integer
  error-status: a :ber/integer type integer representing
  "
  ([]
   (make-pdu (vb/make-variable-binding (oid/make-oid))))
  ([variable-bindings]
   (make-pdu variable-bindings :get (i32/make-integer32 (request-id))))
  ([variable-bindings type]
   (make-pdu variable-bindings type (i32/make-integer32 (request-id)) (i32/make-integer32 0) (i32/make-integer32 0)))
  ([variable-bindings type request-id]
   (make-pdu variable-bindings type request-id (i32/make-integer32 0) (i32/make-integer32 0)))
  ([variable-bindings type request-id error-status error-index]
   (->PDU variable-bindings type request-id error-status error-index)))

(comment
  ;; Example: Creating a complete PDU for different SNMP operations

  ;; Basic GET request for system description
  (let [sys-descr-oid (oid/make-oid "1.3.6.1.2.1.1.1.0")
        var-binding   (vb/make-variable-binding sys-descr-oid)
        pdu           (make-pdu [var-binding] :get)]
    pdu)

  ;; GET request for multiple OIDs
  (let [oids         [(oid/make-oid "1.3.6.1.2.1.1.1.0") ;; sysDescr
                      (oid/make-oid "1.3.6.1.2.1.1.2.0") ;; sysObjectID
                      (oid/make-oid "1.3.6.1.2.1.1.3.0")] ;; sysUpTime
        var-bindings (vb/make-variable-bindings oids)
        pdu          (make-pdu var-bindings :get)]
    pdu)

  )