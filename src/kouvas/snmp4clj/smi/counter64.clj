(ns kouvas.snmp4clj.smi.counter64
  (:require [kouvas.snmp4clj.ber :as ber]))

;; Constants and two's complement conversion logic moved to ber.clj for better architectural separation

(defrecord Counter64 [value type])

(extend Counter64
  ber/BERSerializable
  {:encode-ber (fn [this] (ber/encode-unsigned-int64 this))})

(defn make-counter64
  "Constructor for Counter64 SMI variable. 
   
   Accepts any integer value and interprets it as an unsigned 64-bit integer:
   - Positive values (0 to 2^64-1): used directly
   - Negative values: converted via two's complement to unsigned equivalent during encoding
   "
  ([]
   (make-counter64 0))
  ([n]
   (Counter64. n :ber/counter64)))

(comment

  ;; Basic positive values work as expected
  (ber/encode-ber (make-counter64 1234567890))
  ;; => [70 4 73 -96 2 -46]

  (ber/decode-ber-bytes (ber/encode-ber (make-counter64 1234567890)))
  ;; => 1234567890N

  ;; Full unsigned 64-bit range support
  (ber/decode-ber-bytes (ber/encode-ber (make-counter64 max-counter64-value)))
  ;; => 18446744073709551615N

  ;; negative values converted via two's complement
  (make-counter64 -1)
  ;; => Counter64{:value 18446744073709551615N, :type :ber/counter64}

  (make-counter64 -3914541189257109063)
  ;; => Counter64{:value 14532202884452442553N, :type :ber/counter64}

  ;; Perfect round-trip including negative inputs
  (ber/decode-ber-bytes (ber/encode-ber (make-counter64 -3914541189257109063)))
  ;; => 14532202884452442553N (the unsigned equivalent)

  (vec (ber/encode-ber (make-counter64 -3914541189257109063)))
  ;; => [70 9 0 -55 -84 -63 -121 75 -79 -31 -71]
  )