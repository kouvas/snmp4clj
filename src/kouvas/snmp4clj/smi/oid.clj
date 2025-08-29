(ns kouvas.snmp4clj.smi.oid
  (:require [clojure.string :as str]
            [kouvas.snmp4clj.ber :as ber]))

(def ^:const ^:private max-oid-len :ber/max-oid-length) ;; 128
(def ^:const ^:private max-subid-value 0xFFFFFFFF)
(def ^:const ^:private oid-tag :ber/oid)
(def ^:const ^:private null-oid [])

(declare oid-ber->length)

(defrecord OID [value type])

(extend OID
  ber/BERSerializable
  {:encode-ber (fn [this] (ber/encode-oid this))
   :ber-length (fn [this] (oid-ber->length this))})

(defn parse-dotted-string
  "Parse OID from dotted string format, supporting embedded strings"
  [s]
  (let [parts      (str/split s #"\.")
        parse-part (fn [part]
                     (cond
                       (str/starts-with? part "'")
                       (let [content (subs part 1 (dec (count part)))]
                         (mapv int content))
                       :else [(Integer/parseInt part)]))]
    (vec (mapcat parse-part parts))))

(defn make-oid
  "Create an OID from various input types.
  If not value is passed it creates a 'null oid' as
  a vector containing only 0"
  ([]
   (make-oid null-oid))
  ([input]
   (cond
     (sequential? input) (->OID (vec input) oid-tag)   ;; fixme: confirm input is a vector of number and nothing else?
     (string? input) (->OID (parse-dotted-string input) oid-tag)
     (instance? OID input) (->OID (vec (:value input)) oid-tag)
     :else (throw (ex-info "Invalid OID input"
                           {:input          input
                            :type           (type input)
                            :expected-types ["string" "sequence" "OID instance"]}))))
  ([input offset length]
   (->OID (vec (take length (drop offset input))) oid-tag)))

(defn sub-id-length [sub-id]
  "Calculate how many bytes are needed to encode a single sub-identifier."
  [sub-id]
  (let [value (bit-and sub-id 0xFFFFFFFF)]
    (cond
      (< value 0x80) 1                                 ; 7 bits
      (< value 0x4000) 2                               ; 14 bits
      (< value 0x200000) 3                             ; 21 bits
      (< value 0x10000000) 4                           ; 28 bits
      :else 5                                          ; 32 bits
      )))

(defn- length
  "Calculate the BER-encoded length of an OID value (without tag and length bytes).
 Takes a vector of integer subidentifiers and returns the total encoded length."
  [this]
  (let [value (:value this)]
    (cond
      (empty? value) 1
      (= 1 (count value)) 1
      :else
      ;; for first 2 subids, one sub-id is saved by special encoding
      (let [first-two-length  (sub-id-length (+ (* (first value) 40) (second value)))
            remaining-lengths (map sub-id-length (drop 2 value))]
        (reduce + first-two-length remaining-lengths)))))

(defn- oid-ber->length
  [this]
  (let [length (length this)
        space  (ber/ber-length-of-length length)]
    (+ length space 1)))

(defn oid-from-parts
  "Create OID from prefix and suffix arrays"
  [prefix-oid suffix-oid]
  (->OID (vec (concat prefix-oid suffix-oid)) oid-tag))

(defn oid-with-suffix
  "Create OID from prefix array and single suffix value"
  [prefix-oid suffix-id]
  (->OID (vec (conj (vec prefix-oid) suffix-id)) oid-tag))

;; Core operations
(defn size [oid]
  (count (:value oid)))

(defn get-at [oid index]
  (get (:value oid) index))

(defn get-unsigned [oid index]
  (bit-and (get-at oid index) max-subid-value))

(defn set-at [oid index val]
  (update-in oid [:value index] (constantly val)))

(defn append
  "Append to OID"
  [oid addition]
  (cond
    (string? addition) (update oid :value #(vec (concat % (parse-dotted-string addition))))
    (instance? OID addition) (update oid :value #(vec (concat % (:value addition))))
    (number? addition) (update oid :value conj addition)
    :else (throw (IllegalArgumentException. "Invalid append argument"))))

(defn append-unsigned [oid sub-id]
  (append oid (bit-and sub-id max-subid-value)))

;; Validation
(defn valid? [oid]
  (let [v   (:value oid)
        len (count v)]
    (and (>= len 2)
         (<= len 128)
         (<= (bit-and (first v) max-subid-value) 2)
         (< (bit-and (second v) max-subid-value) 40))))

;; Comparison
(defn left-most-compare [n oid1 oid2]
  (loop [i 0]
    (cond
      (>= i n) 0
      (>= i (min (size oid1) (size oid2)))
      (cond
        (> n (size oid1)) -1
        (> n (size oid2)) 1
        :else 0)
      :else
      (let [v1 (get-at oid1 i)
            v2 (get-at oid2 i)]
        (if (not= v1 v2)
          (if (< (bit-and v1 max-subid-value) (bit-and v2 max-subid-value)) -1 1)
          (recur (inc i)))))))

(defn compare-oids [oid1 oid2]
  (let [min-len (min (size oid1) (size oid2))
        result  (left-most-compare min-len oid1 oid2)]
    (if (zero? result)
      (- (size oid1) (size oid2))
      result)))

(defn starts-with? [oid other]
  (and (<= (size other) (size oid))
       (zero? (left-most-compare (size other) oid other))))

;; Operations
(defn last-subid [oid]
  (when (pos? (size oid))
    (last (:value oid))))

(defn last-unsigned [oid]
  (when-let [last-val (last-subid oid)]
    (bit-and last-val max-subid-value)))

(defn remove-last [oid]
  (if (empty? (:value oid))
    oid
    (update oid :value #(vec (butlast %)))))

(defn trim
  "Remove n rightmost sub-identifiers"
  [oid n]
  (if (pos? n)
    (update oid :value #(vec (take (max 0 (- (count %) n)) %)))
    oid))

(defn trim-last [oid]
  (trim oid 1))

(defn successor
  "Returns the successor OID"
  [oid]
  (let [v (:value oid)]
    (cond
      (= (count v) max-oid-len)
      (loop [i (dec max-oid-len)]
        (if (< i 0)
          (make-oid)
          (if (not= (v i) max-subid-value)
            (make-oid (conj (vec (take (inc i) v)) (inc (v i))))
            (recur (dec i)))))

      :else
      (make-oid (conj v 0)))))

(defn predecessor
  "Returns the predecessor OID"
  [oid]
  (if (and (pos? (size oid)) (zero? (last-subid oid)))
    (remove-last oid)
    (let [v    (:value oid)
          pval (vec (concat v (repeat (- max-oid-len (count v)) max-subid-value)))]
      (set-at (make-oid pval) (dec (size oid)) (dec (last-subid oid))))))

(defn next-peer
  "Returns next OID on same or upper level"
  [oid]
  (cond
    (and (pos? (size oid)) (not= (last-subid oid) max-subid-value))
    (set-at oid (dec (size oid)) (inc (last-subid oid)))

    (> (size oid) 1)
    (next-peer (trim oid 1))

    :else oid))

(defn get-suffix
  "Get suffix of this OID that exceeds the given prefix"
  [oid prefix]
  (when (zero? (left-most-compare (size prefix) oid prefix))
    (make-oid (vec (drop (size prefix) (:value oid))))))

(defn sub-oid
  "Returns sub-sequence of this OID"
  ([oid begin-index]
   (make-oid (vec (drop begin-index (:value oid)))))
  ([oid begin-index end-index]
   (make-oid (vec (take (- end-index begin-index)
                        (drop begin-index (:value oid)))))))

;; String representations
(defn to-string [oid]
  (str/join "." (:value oid)))

(defn to-dotted-string [oid]
  (to-string oid))

(defn to-byte-array [oid]
  (byte-array (map #(byte (bit-and % 0xFF)) (:value oid))))

(defn to-int-array [oid]
  (int-array (:value oid)))

(defn to-unsigned-long-array [oid]
  (long-array (map #(bit-and % max-subid-value) (:value oid))))

;; Utility functions
(defn max-oid [a b]
  (if (>= (compare-oids a b) 0) a b))

(defn min-oid [a b]
  (if (<= (compare-oids a b) 0) a b))


(comment
  (mapv make-oid ["1.2.3.4.5.5" "1.2.3.4.5.5"])
  (make-oid ["2.2.2.2.2"])
  (ber/encode-ber (make-oid ["1.1.1.1"]))
  )