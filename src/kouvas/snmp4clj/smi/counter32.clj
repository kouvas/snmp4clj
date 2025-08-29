"allows all the functionality of unsigned integers but
is recognized as a distinct SMI type, which is used for
monotonically increasing values that wrap around at 2^32-1 (4294967295).
"
(ns kouvas.snmp4clj.smi.counter32
  (:require [kouvas.snmp4clj.ber :as ber]))

(def ^:const max-counter32-value 4294967295)


(defrecord Counter32 [value type])

(extend Counter32
  ber/BERSerializable
  {:encode-ber (fn [this] (ber/encode-unsigned-integer this))})

(defn make-counter32
  "Constructor for Counter32 SMI variable. Counter32 is an unsigned 32-bit integer (0 to 4294967295)."
  ([]
   (make-counter32 0))
  ([n]
   (when (or (< n 0) (> n max-counter32-value))
     (throw (IllegalArgumentException.
              (str "Counter32 value must be between 0 and " max-counter32-value ", got: " n))))
   (Counter32. n :ber/counter32)))

(comment

  (ber/decode-ber
    (ber/encode-unsigned-integer
      (make-counter32 max-counter32-value)))

  )
