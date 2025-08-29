(ns kouvas.snmp4clj.smi.null
  (:require [kouvas.snmp4clj.ber :as ber]
            [kouvas.snmp4clj.variable :as p]
            [kouvas.snmp4clj.tags :as t]))


(def valid-null-types #{:ber/null :ber/no-such-object :ber/no-such-instance :ber/end-of-mib-view})

(defrecord Null [type])

(extend Null
  p/Variable
  (merge
    p/default-variable-behaviour
    {:to-string (fn [this] (t/->syntax-str (:type this)))})

  ber/BERSerializable
  {:encode-ber (fn [this] (ber/encode-null this))
   ;; length is always 2 for Null since it has no value, one byte for tag type on for value length(0)
   :ber-length (fn [_] 2)})

(defn make-null
  ([]
   (make-null :ber/null))
  ([type]
   (if (contains? valid-null-types type)
     (->Null type)
     (throw (IllegalArgumentException. (format "Invalid tag type of < %s > for Null SMI type" type))))))



(comment

  (def nn (make-null :ber/no-such-object))
  (keys nn)
  (get t/ber :ber/no-such-object)
  nn
  (ber/encode-ber nn)
  )