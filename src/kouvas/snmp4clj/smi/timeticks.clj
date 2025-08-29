"represents the time in 1/100 seconds since some epoch (which should
be have been defined in the corresponding MIB specification)."
(ns kouvas.snmp4clj.smi.timeticks
  (:require [kouvas.snmp4clj.ber :as ber]))

(defrecord TimeTicks [value type])

(extend TimeTicks
  ber/BERSerializable
  {:encode-ber (fn [this] (ber/encode-unsigned-integer this))})


(defn make-timeticks
  ([]
   (make-timeticks 0))
  ([n]
   (TimeTicks. n :ber/timeticks)))




(comment
  (ber/decode-timeticks [54 -34 21])
  ;; => "9:59:17.97"
  )
