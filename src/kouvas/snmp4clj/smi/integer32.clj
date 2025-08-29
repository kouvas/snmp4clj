(ns kouvas.snmp4clj.smi.integer32
  "BER encoding of integer32 type. Encoded and serialised as hex bytes always.
  - return type is of byte array where:
    - first byte is the type tag,
    - second byte denotes the length, short or long, form of the next type, the actual value
      i.e whether the value needs one or two bytes to be encoded
  - integers must be encoded in the shortest two compliment
  - SNMP only supports 32bit integer for integer variable type according to RFCs
  https://www.rfc-editor.org/rfc/rfc2578.html#section-7.1.1
  "
  (:require [kouvas.snmp4clj.ber :as ber]
            [kouvas.snmp4clj.variable :as p]))

(defrecord Integer32 [value type])

(defn ber-length
  [this]
  (let [n (:value this)]
    (cond
      (and (< n 0x80)
           (>= n -0x80)) 3
      (and (< n 8000)
           (>= n -8000)) 4
      (and (< n 0x800000)
           (>= n -0x800000)) 5
      :default 6)))

(extend Integer32
  p/Variable
  p/default-variable-behaviour

  ber/BERSerializable
  {:encode-ber (fn [this] (ber/encode-integer this))
   :ber-length (fn [this] (ber-length this))})

(defn make-integer32
  "Constructor for Integer32 SMI variable"
  ([]
   (make-integer32 0))
  ([n]
   (Integer32. (int n) :ber/integer)))


(comment
  (int 34322423343242424)
  (make-integer32 -3)
  (def int32 (make-integer32 Integer/MAX_VALUE))
  (p/syntax int32)
  (keys int32)
  (.value int32)
  (p/encode-ber int32)
  (p/encode-ber (make-integer32 913))

  (-> int32
      (assoc :encoded (p/encode-ber int32))
      (assoc :ber-length (count (:encoded int32)))
      )

  (as-> int32 $
        (assoc $ :encoded (p/encode-ber $))
        (assoc $ :length (count (:encoded $))))

  (p/decode-ber int32)
  (p/decode-ber [2 4 11 53 -14 34])

  int32
  (= 2 0x02))

(comment
  (byte 111)

  (defn inspect-encoded-type
    [t]
    (let [encoded     (p/encode-ber t)
          encoded-vec (vec encoded)]

      ;; Print detailed information
      (println (format "Value: %d" t))
      (println (format "  Hex representation (signed, two's compliment for neg int): 0x%08X" t))
      (println (format "  Binary (int): %s" (Integer/toBinaryString t)))
      (println (format "  Actual encoded length: %d bytes" (count encoded)))
      (println (format "  Encoded bytes (hex, T.L.V, ): [%s]"
                       (clojure.string/join " "
                                            (map #(format "0x%02X" (bit-and % 0xFF))
                                                 encoded))))
      (println (format "  Encoded bytes (dec): %s" encoded-vec))

      ;; Break down the encoding
      (when (>= (count encoded) 2)
        (let [type-byte   (first encoded)
              length-byte (second encoded)
              value-bytes (drop 2 encoded)]
          (println (format "  Breakdown: Type=0x%02X, Length=0x%02X"
                           (bit-and type-byte 0xFF)
                           (bit-and length-byte 0xFF)))
          (when (seq value-bytes)
            (println (format "    Value bytes: [%s]"
                             (clojure.string/join " "
                                                  (map #(format "0x%02X" (bit-and % 0xFF))
                                                       value-bytes)))))))))

  (inspect-encoded-type (make-integer32 1)))
