(ns kouvas.snmp4clj.smi.octet-string
  (:require [kouvas.snmp4clj.ber :as ber]
            [kouvas.snmp4clj.variable :as p]))


; https://www.rfc-editor.org/rfc/rfc2578#section-7.1.2

(defrecord OctetString [^bytes value type])

(defn- octet-str->length
  [this]
  (let [length (count (:value this))
        space  (ber/ber-length-of-length length)]
    (+ length space 1)))

(extend OctetString
  ber/BERSerializable
  {:encode-ber (fn [this] (ber/encode-oct-str this))
   :ber-length (fn [this] (octet-str->length this))})

(extend OctetString p/Variable p/default-variable-behaviour)

(defn octet-string-from-string
  "Creates an OctetString from a Java string"
  [s]
  (->OctetString s :ber/octet-string))

(defn octet-string-copy
  "Creates a copy of another OctetString"
  [os]
  (->OctetString (byte-array (:value os)) :ber/octet-string))

(defn make-octet-string
  "Creates an OctetString from various input types"
  ([]
   (make-octet-string (byte-array 0) :ber/octet-string))

  ([input]
   (cond
     (bytes? input) (->OctetString input :ber/octet-string)
     (string? input) (octet-string-from-string input)
     (instance? OctetString input) (octet-string-copy input)
     :else (throw (ex-info "Invalid octet string input"
                           {:input          input
                            :type           (type input)
                            :expected-types ["string" "bytes" "OctetString instance"]}))))

  ;;Creates a concatenated octet string from two byte arrays
  ([prefix-array suffix-array]
   (if (nil? suffix-array)
     (->OctetString (byte-array prefix-array) :ber/octet-string)
     (let [prefix-len (alength prefix-array)
           suffix-len (alength suffix-array)
           result     (byte-array (+ prefix-len suffix-len))]
       (System/arraycopy prefix-array 0 result 0 prefix-len)
       (System/arraycopy suffix-array 0 result prefix-len suffix-len)
       (->OctetString result :ber/octet-string))))

  ([bytes-array offset length]
   (let [result (byte-array length)]
     (System/arraycopy bytes-array offset result 0 length)
     (->OctetString result :ber/octet-string))))



(comment
  (def o (make-octet-string "test"))
  (keys o)
  (:value o)
  (ber/encode-ber o)
  (ber/ber-length o)
  (ber/decode-ber (ber/encode-ber o))
  (def ooo (make-octet-string (apply str (repeat 200 "X"))))
  ooo
  ;; long form length
  (ber/encode-ber ooo)
  (ber/ber-length ooo)
  (count (ber/encode-ber ooo))
  )