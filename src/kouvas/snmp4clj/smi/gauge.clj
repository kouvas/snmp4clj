"Similarly to Counter32 and Timeticks, Gauge32 used unsigned integers"
(ns kouvas.snmp4clj.smi.gauge
  (:require [kouvas.snmp4clj.ber :as ber]))


(def ^:const max-counter32-value 4294967295)

(defrecord Gauge [value type])

(extend Gauge
  ber/BERSerializable
  {:encode-ber (fn [this] (ber/encode-unsigned-integer this))})


(defn make-gauge32
  "Constructor for Counter32 SMI variable. Counter32 is an unsigned 32-bit integer (0 to 4294967295)."
  ([]
   (make-gauge32 0))
  ([n]
   (when (or (< n 0) (> n max-counter32-value))
     (throw (IllegalArgumentException.
              (str "Counter32 value must be between 0 and " max-counter32-value ", got: " n))))
   (Gauge. n :ber/gauge32)))


