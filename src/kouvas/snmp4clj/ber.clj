(ns kouvas.snmp4clj.ber
  (:require [clojure.string :as string]
            [kouvas.snmp4clj.tags :as t :refer [ber pdu]]
            [kouvas.snmp4clj.utils :as u])
  (:import (java.net Inet6Address)))

(def ^:const minimum-pdu-length 484)
(def ^:const max-pdu-length 65535)

;; ============================================================================
;; BER protocol
;; ============================================================================

;; protocol should be in same ns as the encode fns to avoid cyclic dependency because
(defprotocol BERSerializable
  "All SMI data types are BERSerializable. On top of that a map with keys tag, length, value,
  is also BERSerializable"
  (encode-ber [this] "Encodes this value to a vector of bytes")
  (decode-ber [this] "Decodes a vector of ASN.1 bytes")
  (ber-length [this] "Returns the BER encoded length of this variable including the tag length and value bytes")
  (ber-payload-length [this] "Returns the BER encoded length of this variables value(bytes)/payload"))

(defn encode-length
  "Encodes the length of an ASN.1 object and returns a vector of decimal bytes.
  The maximum length is 0xFFFFFFFF"
  ([length]
   (cond
     ;; Negative length - use 4-byte long form
     (neg? length)
     [(unchecked-byte (bit-or 0x04 t/asn1-long-length))
      (unchecked-byte (bit-and (bit-shift-right length 24) 0xFF))
      (unchecked-byte (bit-and (bit-shift-right length 16) 0xFF))
      (unchecked-byte (bit-and (bit-shift-right length 8) 0xFF))
      (unchecked-byte (bit-and length 0xFF))]

     ;; Short form - single byte
     (< length 0x80)
     [(unchecked-byte length)]

     ;; Long form - 1 byte length
     (<= length 0xFF)
     [(unchecked-byte (bit-or 0x01 t/asn1-long-length))
      (unchecked-byte length)]

     ;; Long form - 2 byte length
     (<= length 0xFFFF)
     [(unchecked-byte (bit-or 0x02 t/asn1-long-length))
      (unchecked-byte (bit-and (bit-shift-right length 8) 0xFF))
      (unchecked-byte (bit-and length 0xFF))]

     ;; Long form - 3 byte length
     (<= length 0xFFFFFF)
     [(unchecked-byte (bit-or 0x03 t/asn1-long-length))
      (unchecked-byte (bit-and (bit-shift-right length 16) 0xFF))
      (unchecked-byte (bit-and (bit-shift-right length 8) 0xFF))
      (unchecked-byte (bit-and length 0xFF))]

     ;; Long form - 4 byte length
     :else
     [(unchecked-byte (bit-or 0x04 t/asn1-long-length))
      (unchecked-byte (bit-and (bit-shift-right length 24) 0xFF))
      (unchecked-byte (bit-and (bit-shift-right length 16) 0xFF))
      (unchecked-byte (bit-and (bit-shift-right length 8) 0xFF))
      (unchecked-byte (bit-and length 0xFF))]))

  ([length num-length-bytes]
   ;; Explicit number of length bytes specified
   (into [(unchecked-byte (bit-or num-length-bytes t/asn1-long-length))]
         (for [i (range (dec num-length-bytes) -1 -1)]
           (unchecked-byte (bit-and (bit-shift-right length (* i 8)) 0xFF))))))

(defn ber-length-of-length
  "Computes the space, in bytes, needed to encode an integer that
  represents the length of the actual value of a BER type."
  [^Long length]
  (cond
    (< length 0) 5
    (< length 0x80) 1
    (<= length 0xFF) 2
    (<= length 0xFFFF) 3
    (<= length 0xFFFFFF) 4
    :else 5))

(defn encode-header
  "Returns a vector of decimal bytes that include the tag bytes
  and the bytes of the encoded length of the value to be encoded.
  The header includes the T.L parts of T.L.V encoded data types"
  [tag-byte length]
  (into [tag-byte] (encode-length length)))

(defn encode-sequence
  "Expects a vector of vectors, each one representing an encoded SNMP variable
Merges encoded data and returns them as encoded sequence"
  [encoded-elements]
  (let [tag-byte      (get ber :ber/sequence)
        content-bytes (vec (apply concat encoded-elements))
        header        (encode-header tag-byte (count content-bytes))]
    (into header content-bytes)))

(defn decode-length
  "Parses BER-encoded length from a byte sequence with comprehensive validation.
   Returns [length remaining-bytes] for both short and long form."
  [byte-seq]

  (let [first-byte (bit-and (first byte-seq) 0xFF)]
    (cond
      ;; Short form: MSB = 0, length is the byte value itself
      (< first-byte 0x80)
      [first-byte (rest byte-seq)]

      ;; Indefinite length form (0x80) - not allowed in SNMP
      (= first-byte 0x80)
      (throw (ex-info "Indefinite length encoding not supported in SNMP"
                      {:error :indefinite-length :byte first-byte}))

      ;; Long form: MSB = 1, remaining bits indicate number of length bytes
      :else
      (let [num-length-bytes (bit-and first-byte 0x7F)
            remaining-bytes  (rest byte-seq)]

        ;; Validate indefinite length indicator again inside long form branch now
        (when (zero? num-length-bytes)
          (throw (ex-info "Indefinite length encoding not supported in SNMP"
                          {:error :indefinite-length-indicator})))

        ;; Validate maximum length bytes (SNMP constraint)
        (when (> num-length-bytes 4)
          (throw (ex-info "Length encoding exceeds 4 bytes (SNMP limitation)"
                          {:error       :length-too-long
                           :num-bytes   num-length-bytes
                           :max-allowed 4})))

        ;; Validate sufficient bytes available
        (when (< (count remaining-bytes) num-length-bytes)
          (throw (ex-info "Insufficient bytes for length encoding"
                          {:error     :incomplete-length
                           :required  num-length-bytes
                           :available (count remaining-bytes)})))

        ;; Calculate length value from length bytes
        (let [length-bytes      (take num-length-bytes remaining-bytes)
              calculated-length (->> length-bytes
                                     (map #(bit-and % 0xFF))
                                     (reduce #(bit-or (bit-shift-left %1 8) %2) 0))
              rest-bytes        (drop num-length-bytes remaining-bytes)]

          ;; Validate calculated length (SNMP constraint)
          (when (neg? calculated-length)
            (throw (ex-info "Calculated length exceeds 2^31 (SNMP limitation)"
                            {:error             :length-overflow
                             :calculated-length calculated-length})))

          [calculated-length rest-bytes])))))

(defn encode-null
  [this]
  (let [tag-byte (unchecked-byte (get ber (:type this)))]
    ;; Null value length is always zero
    (encode-header tag-byte 0)))

(defn encode-string
  [tag-byte bytes]
  (into
    (encode-header tag-byte (count bytes))
    bytes))

(defn encode-oct-str
  [this]
  (let [tag-byte (byte (get ber (:type this)))
        bytes    (if (bytes? (:value this))
                   (:value this)
                   (vec (.getBytes (:value this))))]
    (encode-string tag-byte bytes)))

(defn encode-ip-address [this]
  (when (instance? Inet6Address (:inet-address this))
    (throw (ex-info "IPv6 addresses not supported yet" {:error :unsupported-ipv6-address})))
  (let [tag-byte (get ber (:type this))
        bytes    (->> (:inet-address this)
                      (.getAddress)
                      (vec))]
    (encode-string tag-byte bytes)))

(defn encode-opague
  [this]
  (let [tag-byte (:type this)
        bytes    (:value this)]
    (encode-string tag-byte bytes)))

(defn encode-integer
  "Accepts an Integer32 record datatype in order to be encoded as per BER rules.
   Returns a map with :tag, :length, and :value keys"
  [this]
  (let [n        (:value this)
        tag-byte (byte (get ber (:type this)))
        ;; Convert to bytes in big-endian format
        bytes    (cond
                   ;; Zero special case
                   (zero? n)
                   [(byte 0x00)]

                   ;; Positive numbers
                   (pos? n)
                   (let [;; Convert to big-endian byte sequence
                         byte-vec   (loop [num n
                                           acc []]
                                      (if (zero? num)
                                        (reverse acc)
                                        (recur (bit-shift-right num 8)
                                               (conj acc (unchecked-byte (bit-and num 0xFF))))))
                         ;; Check if we need padding (high bit set on first byte)
                         first-byte (first byte-vec)]
                     (if (bit-test first-byte 7)       ; Check if high bit is set
                       (into [(byte 0x00)] byte-vec)   ; Add padding
                       byte-vec))

                   :else
                   (let [;; For negative numbers, we need to find minimal two's complement representation
                         ;; Start with -1 (all bits set) and shift until we can represent our number
                         byte-vec (loop [num n
                                         acc []]
                                    (let [byte-val (bit-and num 0xFF)]
                                      (if (and (= (bit-shift-right num 8) -1) ; Rest is all 1s
                                               (bit-test byte-val 7)) ; High bit is set
                                        ;; We can stop here
                                        (reverse (conj acc (unchecked-byte byte-val)))
                                        ;; Need more bytes
                                        (recur (bit-shift-right num 8)
                                               (conj acc (unchecked-byte byte-val))))))]
                     byte-vec))]
    (into (encode-header tag-byte (count bytes)) bytes)))

(defn encode-unsigned-integer
  [this]
  (let [value    (:value this)
        tag-byte (byte (get ber (:type this)))
        lenmask  (:ber/lenmask ber)
        length   (let [base-len (cond
                                  (not= 0 (bit-and (bit-shift-right value 24) lenmask)) 4
                                  (not= 0 (bit-and (bit-shift-right value 16) lenmask)) 3
                                  (not= 0 (bit-and (bit-shift-right value 8) lenmask)) 2
                                  :else 1)]
                   ;; Add extra byte if high bit would be set
                   (if (not= 0 (bit-and (bit-shift-right value (* 8 (dec base-len))) 0x80))
                     (inc base-len)
                     base-len))
        bytes    (if (= length 5)
                   ;; Special case: 5 bytes with leading null
                   (into [(byte 0)]
                         (for [x (range 1 length)]
                           (unchecked-byte (bit-and (bit-shift-right value (* 8 (- 4 x))) lenmask))))
                   ;; Normal case: len bytes
                   (for [x (range length)]
                     (unchecked-byte (bit-and (bit-shift-right value (* 8 (- (dec length) x))) lenmask))))]
    (into (encode-header tag-byte length) bytes)))

(defn encode-unsigned-int64
  "Encodes Counter64 as unsigned 64-bit integer using raw bit manipulation.
   Takes raw long bits and encodes directly."
  [this]
  (let [value    (long (:value this))                  ; Ensure we have a long for bit operations
        tag-byte (byte (get ber (:type this)))
        lenmask  (:ber/lenmask ber)

        ;; Calculate minimum bytes needed
        ;; Truncate unnecessary bytes from most significant end
        len      (loop [len 8]
                   (if (and (> len 1)
                            (= 0 (bit-and (bit-shift-right value (* 8 (dec len))) 0xFF)))
                     (recur (dec len))
                     len))

        ;; Add extra byte if high bit is set (to avoid sign bit interpretation)
        len      (if (not= 0 (bit-and (bit-shift-right value (* 8 (dec len))) 0x80))
                   (inc len)
                   len)

        ;; Generate bytes using bit shifts
        bytes    (if (= len 9)
                   ;; 9-byte case: leading zero + 8 value bytes
                   (cons (byte 0)
                         (for [x (range 1 len)]
                           (unchecked-byte (bit-and (bit-shift-right value (* 8 (- 8 x))) lenmask))))
                   ;; Normal case: extract bytes using bit shifts
                   (for [x (range len)]
                     (unchecked-byte (bit-and (bit-shift-right value (* 8 (- (dec len) x))) lenmask))))]
    (into (encode-header tag-byte len) bytes)))

(defn- encode-subid
  "Encode a single OID subidentifier using 7-bit chunks with MSB continuation.
   Returns a vector of bytes."
  [subid]
  (let [subid-long (bit-and subid 0xFFFFFFFF)]
    (if (< subid-long 128)
      ;; Fits in single byte
      [(unchecked-byte subid-long)]
      ;; Multi-byte encoding
      ;; Build bytes in reverse order, then reverse at the end
      (let [bytes (loop [value  subid-long
                         acc    []
                         first? true]
                    (let [low-7-bits (bit-and value 0x7F)
                          remaining  (bit-shift-right value 7)]
                      (if (zero? remaining)
                        ;; This is the most significant chunk - add with MSB=1
                        (conj acc (unchecked-byte (bit-or 0x80 low-7-bits)))
                        ;; More chunks to process
                        (recur remaining
                               (conj acc (unchecked-byte (if first? low-7-bits (bit-or 0x80 low-7-bits))))
                               false))))]
        (vec (reverse bytes))))))

(defn encode-oid
  "Encode an OID to BER format.
   Returns a vector of bytes including tag, length, and encoded value."
  [this]
  (let [tag-byte       (unchecked-byte (get ber (:type this)))
        oid-values     (:value this)
        ;; Handle edge cases
        encoded-values (cond
                         ;; Empty or single element OID
                         (< (count oid-values) 2)
                         [(unchecked-byte 0x00)]

                         ;; Normal OID encoding
                         :else
                         (let [first-val  (first oid-values)
                               second-val (second oid-values)]
                           ;; Validate first component
                           (when (or (< first-val 0) (> first-val 2))
                             (throw (ex-info "Invalid first sub-identifier (must be 0, 1, or 2)"
                                             {:first first-val})))
                           ;; Validate second component for first=0,1
                           (when (and (<= first-val 1) (> second-val 39))
                             (throw (ex-info "Invalid second sub-identifier (must be 0-39 when first is 0 or 1)"
                                             {:first first-val :second second-val})))

                           ;; Encode first two components together
                           (let [first-byte (+ (* first-val 40) second-val)
                                 ;; Encode remaining components
                                 remaining  (mapcat encode-subid (drop 2 oid-values))]
                             (into (encode-subid first-byte) remaining))))]
    (into (encode-header tag-byte (count encoded-values))
          encoded-values)))

(defn encode-var-bind
  [this]
  (let [oid (encode-ber (:oid this))
        var (encode-ber (:variable this))]
    (encode-sequence [oid var])))

(defn encode-pdu
  ;; extract and encode var binds
  ;; encode sequence of var bind list, i.e. it's header the bytes of encoded var binds as value
  ;; encode type, request id, error index, error status
  ;; encode hear and return concatenated encodings
  [this]
  (let [tag-byte     (get pdu (:type this))
        request-id   (encode-ber (:request-id this))
        error-status (encode-ber (:error-status this))
        error-index  (encode-ber (:error-index this))
        var-binds    (encode-sequence (mapv encode-ber (:variable-bindings this)))
        pdu-body     (reduce into [request-id error-status error-index var-binds])]
    (into (encode-header tag-byte (count pdu-body)) pdu-body)))

(defn encode-snmp-payload
  [version community pdu]
  (try
    (let [version   (encode-ber version)
          community (encode-ber community)
          pdu-bytes (encode-ber pdu)
          payload   (encode-sequence [version community pdu-bytes])]
      payload)
    (catch Exception e (str "Payload encoding failed: " (.getMessage e) "\n" (.getCause e)
                            "version " version "\ncommunity " community))))

(defn decode-null []
  ;; Null, NoSuchObject, NoSuchInstance, EndOfMibView
  nil)

(defn decode-integer
  "Decodes integer value from raw value bytes (without tag and length).
  Returns the decoded integer value."
  [value-bytes]
  (when (empty? value-bytes)
    (throw (ex-info "Empty value bytes for integer decoding" {})))

  (let [length (count value-bytes)]
    (when (> length 4)
      (throw (ex-info "Length greater than 32bit are not supported for integers"
                      {:error  :invalid-length-for-integer
                       :length length})))

    ;; Read first byte to check sign
    (let [first-byte    (bit-and (first value-bytes) 0xFF)
          ;; If MSB is set, the number is negative
          initial-value (if (bit-test first-byte 7) -1 0)]
      ;; Read all bytes and build the integer
      (loop [i         0
             value     initial-value
             bytes-seq value-bytes]
        (if (< i length)
          (let [b (bit-and (first bytes-seq) 0xFF)]
            (recur (inc i)
                   (bit-or (bit-shift-left value 8) b)
                   (rest bytes-seq)))
          value)))))

(defn decode-unsigned-integer
  "Decodes unsigned integer value from raw value bytes (without tag and length).
   Returns the decoded unsigned integer value."
  [value-bytes]
  (when (empty? value-bytes)
    (throw (ex-info "Empty value bytes for unsigned integer decoding" {})))

  (let [length (count value-bytes)]
    (when (> length 5)
      (throw (ex-info "Length greater than 5 bytes not supported for unsigned integers"
                      {:length length})))

    (reduce (fn [acc byte]
              (bit-or (bit-shift-left acc 8)
                      (bit-and byte 0xFF)))
            0
            value-bytes)))

(defn decode-unsigned-int64
  "Decode Counter64 from value bytes using Clojure core functions.
   Returns BigInteger for full unsigned 64-bit range support."
  [value-bytes]
  (when (empty? value-bytes)
    (throw (ex-info "Empty value bytes for Counter64 decoding" {})))

  (when (> (count value-bytes) 9)
    (throw (ex-info "Counter64 length too large" {:length (count value-bytes)})))

  (reduce (fn [acc byte]
            (let [acc-big  (bigint acc)
                  byte-val (bit-and byte 0xFF)]
              (+ (* acc-big 256) byte-val)))
          (bigint 0)
          value-bytes))

(defn time-parts [ticks]
  (let [days         (quot ticks 8640000)
        remaining    (rem ticks 8640000)
        hours        (quot remaining 360000)
        remaining    (rem remaining 360000)
        minutes      (quot remaining 6000)
        remaining    (rem remaining 6000)
        seconds      (quot remaining 100)
        centiseconds (rem remaining 100)]
    {:days days :hours hours :minutes minutes :seconds seconds :centiseconds centiseconds}))

(defn timeticks->string
  "Convert timeticks value (hundredths of a second) to string format with days support"
  [ticks]
  (let [{:keys [days hours minutes seconds centiseconds]} (time-parts ticks)]
    (str (cond
           (zero? days) ""
           (= days 1) "1 day, "
           :else (str days " days, "))
         (format "%d:%02d:%02d.%02d" hours minutes seconds centiseconds))))

(defn ->timeticks-to-string
  [byte-seq]
  (-> byte-seq
      timeticks->string))

(defn decode-timeticks
  "Decode SNMP TimeTicks from a byte sequence.
   Returns the time value in hundredths of a second."
  [byte-seq]
  (when (empty? byte-seq)
    (throw (ex-info "Cannot decode from empty byte sequence"
                    {:error :empty-input})))
  (->timeticks-to-string
    (decode-unsigned-integer byte-seq)))

(defn decode-string
  [value-bytes]
  (String. (byte-array value-bytes) "UTF-8"))

(defn decode-ip-address [value-bytes]
  (when (not= 4 (count value-bytes))
    (throw (ex-info "IP address must be exactly 4 bytes"
                    {:error  :invalid-ip-length
                     :length (count value-bytes)})))
  (->> value-bytes
       ; Convert signed bytes to unsigned
       (map #(u/signed->unsigned %))
       (string/join ".")))

(defn decode-opaque-double [data-bytes]
  (when (not= 8 (count data-bytes))
    (throw (ex-info "Double must be exactly 8 bytes"
                    {:error  :invalid-double-length
                     :length (count data-bytes)})))
  (let [;; Copy bytes and convert each 32-bit half with ntohl (network to host byte order)
        int0         (bit-or (bit-shift-left (nth data-bytes 0) 24)
                             (bit-shift-left (nth data-bytes 1) 16)
                             (bit-shift-left (nth data-bytes 2) 8)
                             (nth data-bytes 3))
        int1         (bit-or (bit-shift-left (nth data-bytes 4) 24)
                             (bit-shift-left (nth data-bytes 5) 16)
                             (bit-shift-left (nth data-bytes 6) 8)
                             (nth data-bytes 7))
        ;; Net-SNMP swaps the two halves:
        ;; tmp = ntohl(intVal[0]); intVal[0] = ntohl(intVal[1]); intVal[1] = tmp;
        swapped-long (bit-or (bit-shift-left (long int1) 32)
                             (bit-and (long int0) 0xFFFFFFFF))]
    (Double/longBitsToDouble swapped-long)))

(defn decode-opaque-signed-int64 [data-bytes]
  (let [length (count data-bytes)]
    (when (zero? length)
      (throw (ex-info "Empty value bytes"
                      {:error :empty-value-bytes})))
    (when (> length 8)
      (throw (ex-info "Signed int64 too large"
                      {:length length :max-supported 8})))
    (cond
      (<= length 4) (decode-integer data-bytes)
      (<= length 8) (let [first-byte    (bit-and (first data-bytes) 0xFF)
                          ;; Sign extend: if MSB is set, start with -1, else 0
                          initial-value (if (bit-test first-byte 7) -1 0)]
                      (reduce (fn [acc byte]
                                (bit-or (bit-shift-left acc 8)
                                        (bit-and byte 0xFF)))
                              initial-value
                              data-bytes)))))

(defn opaque-subtype? [unsigned-bytes]
  (and (>= (count unsigned-bytes) 3)
       (= (first unsigned-bytes) (:ber/opaque-subtype ber))))

(defn decode-opaque [value-bytes]
  (let [unsigned-bytes (mapv #(bit-and % 0xFF) value-bytes)]
    (if (opaque-subtype? unsigned-bytes)
      (let [type-tag    (nth unsigned-bytes 1)
            data-length (nth unsigned-bytes 2)
            data-bytes  (vec (drop 3 unsigned-bytes))]

        (or
          (case type-tag
            ;; Float (0x78)
            0x78 (when (and (= data-length 4) (>= (count data-bytes) 4))
                   (let [network-int (bit-or (bit-shift-left (nth data-bytes 0) 24)
                                             (bit-shift-left (nth data-bytes 1) 16)
                                             (bit-shift-left (nth data-bytes 2) 8)
                                             (nth data-bytes 3))]
                     (Float/intBitsToFloat network-int)))

            ;; Double (0x79)
            0x79 (when (and (= data-length 8) (>= (count data-bytes) 8))
                   (decode-opaque-double data-bytes))

            ;; Signed Int64 (0x7A)
            0x7A (when (and (<= data-length 8) (>= (count data-bytes) data-length))
                   (decode-opaque-signed-int64 data-bytes))

            ;; Unsigned Int64 (0x7B)
            0x7B (when (and (<= data-length 8) (>= (count data-bytes) data-length))
                   (decode-unsigned-int64 data-bytes))

            ;; Unknown special type
            nil)

          ;; Fallback
          (byte-array unsigned-bytes)))

      ;; Not a special opaque type - return raw bytes
      (byte-array unsigned-bytes))))

(defn- decode-subid
  "Decode a multi-byte OID subidentifier from bytes starting at position.
   Returns [subid-value new-position]."
  [bytes pos]
  (loop [value       0
         current-pos pos]
    (let [b (bit-and (nth bytes current-pos) 0xFF)]
      (if (bit-test b 7)                               ; MSB = 1, more bytes follow
        (recur (bit-or (bit-shift-left value 7) (bit-and b 0x7F))
               (inc current-pos))
        ;; Last byte (MSB = 0)
        [(bit-or (bit-shift-left value 7) b) (inc current-pos)]))))

(defn decode-oid
  "Decode an OID from raw value bytes (without tag and length).
   Returns a string representation of the OID in dotted notation."
  [value-bytes]
  (let [oid-vector (if (empty? value-bytes)
                     ;; Empty OID
                     []
                     ;; Decode first byte(s) (contains first two subidentifiers)
                     (let [first-byte (bit-and (first value-bytes) 0xFF)
                           ;; Check if the first byte uses multi-byte encoding
                           [combined-value next-pos] (if (bit-test first-byte 7)
                                                       ;; Multi-byte encoding for first two components
                                                       (decode-subid value-bytes 0)
                                                       ;; Single byte encoding
                                                       [first-byte 1])
                           ;; Decode first two components from the combined value
                           [first-id second-id] (cond
                                                  (< combined-value 40) [0 combined-value]
                                                  (< combined-value 80) [1 (- combined-value 40)]
                                                  :else [2 (- combined-value 80)])
                           ;; Decode remaining subidentifiers
                           end-pos    (count value-bytes)]
                       (loop [current-pos next-pos
                              result      [first-id second-id]]
                         (if (>= current-pos end-pos)
                           result
                           (let [[subid new-pos] (decode-subid value-bytes current-pos)]
                             (recur new-pos (conj result subid)))))))]
    (if (empty? oid-vector)
      ""
      (string/join "." oid-vector))))

(declare parse-tlv-sequence)

(defn parse-tlv
  "Parse a complete TLV unit from byte sequence.
   Returns [tag length value-bytes remaining-bytes]"
  [byte-seq]
  (when (seq byte-seq)
    (let [tag (first byte-seq)
          [length rest-after-length] (decode-length (rest byte-seq))
          [value-bytes remaining] (split-at length rest-after-length)]
      [tag length value-bytes remaining])))

(defn bytes->tlv-structure
  "Parse BER structure preserving tag, length, and value information.
   Returns a single map for the top-level structure (always SEQUENCE for SNMP).

   For primitive types: {:tag 2 :length 4 :value [raw-bytes]}
   For constructed types: {:tag 48 :length 42 :value [nested-structures]}"
  [byte-seq]
  (when (seq byte-seq)
    (let [[tag length value-bytes remaining] (parse-tlv byte-seq)]
      (when (seq remaining)
        (throw (ex-info "Illegal extra bytes after TLV structure found" {:error :extra-bytes})))
      (if (bit-test tag 5)
        ;; Constructed type - recursively parse the value
        {:tag    tag
         :length length
         :value  (parse-tlv-sequence value-bytes)}
        ;; Primitive type - keep raw bytes
        {:tag    tag
         :length length
         :value  (vec value-bytes)}))))

(defn parse-tlv-sequence
  "Recursively parses a sequence of TLV structures, returning vector of parsed structures"
  [byte-seq]
  (loop [bytes   byte-seq
         results []]
    (if (empty? bytes)
      results
      (let [[tag length value-bytes remaining] (parse-tlv bytes)
            structure (if (bit-test tag 5)             ; Constructed? todo review
                        {:tag    tag
                         :length length
                         :value  (parse-tlv-sequence value-bytes)}
                        {:tag    tag
                         :length length
                         :value  (vec value-bytes)})]
        (recur remaining (conj results structure))))))

(defn decode-ber-value
  ;; todo validate length vs actual value's length here or in individual decode fns
  "Convert raw BER value bytes to appropriate Clojure primitive types
   based on the tag. Does not create SMI objects - just basic type conversion.
   Uses `case` for dispatching on byte literals for performance reasons"
  [{:keys [tag length value] :as tlv}]
  (when (or (nil? tag) (nil? value))
    ;; todo is it ever going to be nil really?
    (throw (ex-info "BER tag cannot be nil" {:error :invalid-nil-tag})))

  (case (bit-and tag 0xFF)
    0x02 (decode-integer value)
    0x04 (decode-string value)
    (0x05 0x80 0x81 0x82) (decode-null)
    0x06 (decode-oid value)
    0x40 (decode-ip-address value)
    (0x41 0x42) (decode-unsigned-integer value)
    0x43 (decode-timeticks value)
    0x44 (decode-opaque value)
    ;; Counter64
    0x46 (decode-unsigned-int64 value)

    (throw (ex-info "Invalid BER tag returned for decoding" {:error   :invalid-tag
                                                             :tag     tag
                                                             :tag-hex (u/->hex-str tag)}))))

(defn ->opaque-type [variable-val]
  (println variable-val)
  (case (bit-and (second variable-val) 0xFF)
    0x78 :ber/opaque-float
    0x79 :ber/opaque-double
    0x7A :ber/opaque-int64
    0x7b :ber/opaque-uint64
    (throw (ex-info "Invalid BER tag for Opaque variable" {:error :invalid-opaque-tag}))))

(defn decode-variable-binding [tlv]
  (let [[oid-tlv variable-tlv] (:value tlv)
        oid-val       (decode-ber-value oid-tlv)
        variable-val  (decode-ber-value variable-tlv)
        tag           (:tag variable-tlv)
        variable-type (case (bit-and tag 0xFF)
                        0x02 :ber/integer
                        0x03 :ber/bit-str
                        0x04 :ber/octet-string
                        0x05 :ber/null
                        0x06 :ber/oid
                        0x40 :ber/ip-address
                        0x41 :ber/counter32
                        0x42 :ber/gauge32
                        0x43 :ber/timeticks
                        0x44 (->opaque-type (:value variable-tlv))
                        0x46 :ber/counter64
                        0x80 :ber/no-such-object
                        0x81 :ber/no-such-instance
                        0x82 :ber/end-of-mib-view
                        (throw (ex-info "Unable to decode variable due to invalid tag" {:error   :invalid-tag
                                                                                        :tag     tag
                                                                                        :tag-hex (u/->hex-str tag)})))]
    {:oid      {:value oid-val :type :ber/oid}
     :variable {:value variable-val :type variable-type}}))

(defn decode-variable-bindings
  "Decode variable bindings from BER structure"
  [{:keys [tag value] :as structure}]
  (when (= tag 0x30)
    (mapv decode-variable-binding value)))

(defn pdu?
  [tag]
  (let [mask (bit-and tag 0xFF)]
    (and (>= mask 0xA0)
         (<= mask 0xA8))))

(defn decode-pdu
  "Decode PDU from BER structure to complete PDU object"
  [{:keys [tag value] :as tlv}]
  (let [pdu-type          (case (bit-and tag 0xFF)
                            0xA0 :get
                            0xA1 :get-next
                            0xA2 :response
                            0xA3 :set
                            0xA4 :trap-v1
                            0xA5 :get-bulk
                            0xA6 :inform
                            0xA7 :trap
                            0xA8 :report
                            (throw (ex-info "Invalid PDU tag byte" {:error :invalid-pdu-tag
                                                                    :tag   tag})))

        [request-id-tlv error-status-tlv error-index-tlv var-binds-tlv] value

        request-id        (decode-ber-value request-id-tlv)
        error-status      (decode-ber-value error-status-tlv)
        error-index       (decode-ber-value error-index-tlv)
        variable-bindings (decode-variable-bindings var-binds-tlv)]

    {:type              pdu-type
     :request-id        request-id
     :error-status      (case error-status
                          0 :no-error
                          1 :too-big
                          2 :no-such-name
                          3 :bad-value
                          4 :read-only
                          5 :gen-err
                          (throw (ex-info "Invalid error status" {:error :invalid-error-status})))
     :error-index       error-index
     :variable-bindings variable-bindings}))

(defn snmp-message? [tlv]
  (and (= 0x30 (:tag tlv))                             ; SEQUENCE
       (= 3 (count (:value tlv)))                      ; Exactly 3 elements
       (= 0x02 (:tag (first (:value tlv))))            ; First is INTEGER (version)
       (= 0x04 (:tag (second (:value tlv))))           ; Second is OCTET_STRING (community)
       (pdu? (:tag (last (:value tlv))))))             ; PDU

(defn decode-snmp-message [tlv]
  (let [[version-tlv community-tlv pdu-tlv] (:value tlv)
        version-val   (decode-ber-value version-tlv)
        community-val (decode-ber-value community-tlv)
        pdu           (decode-pdu pdu-tlv)]
    {:version   (case version-val
                  0 :snmp/v1
                  1 :snmp/v2c
                  3 :snmp/v3
                  (throw (ex-info "Invalid SNMP version value" {:error   :invalid-snmp-version
                                                                :version version-val})))
     :community community-val
     :pdu       pdu}))

(defn variable-bindings?
  "Check if a structure represents a sequence of variable bindings.
   Variable bindings are sequences where each element is a sequence containing:
   1. An OID (tag 0x06)
   2. Any (SMI) variable (any valid smi tag)"
  [{:keys [tag value]}]
  (and (= 0x30 tag)
       (every? (fn [binding]
                 (and (= 0x30 (:tag binding))
                      (= 2 (count (:value binding)))
                      (= 0x06 (:tag (first (:value binding))))))
               value)))

(defn decode-tlv
  [{:keys [tag length value] :as tlv}]
  (cond
    (pdu? tag)
    (decode-pdu tlv)

    (variable-bindings? tlv)
    (decode-variable-bindings tlv)

    :else
    (decode-ber-value tlv)))

(defn decode-ber-bytes
  [byte-vec]
  (let [tlv (bytes->tlv-structure (seq byte-vec))]
    (if (snmp-message? tlv)
      (decode-snmp-message tlv)
      (decode-tlv tlv))))

(extend
  clojure.lang.PersistentVector
  BERSerializable
  {:decode-ber (fn [bytes] (decode-ber-bytes bytes))})

(comment
  (try
    (decode-ber-bytes [2 1 1])
    (catch Exception e
      (ex-data e)))
  (decode-ber-bytes [-94 29
                     2 4 124 -67 52 -8 2 1 0 2 1 0 48 15 48 13 6 8 43 6 1 2 1 1 7 0 2 1 88])
  (decode-ber-bytes [48 15 48 13 6 8 43 6 1 2 1 1 7 0 2 1 88])
  (decode-ber-bytes [4 6 112 117 98 108 105 99])

  (def sysServices [48 42
                    2 1 1
                    4 6 112 117 98 108 105 99
                    -94 29
                    2 4 124 -67 52 -8 2 1 0 2 1 0 48 15
                    48 13
                    6 8 43 6 1 2 1 1 7 0
                    2 1 88])
  [48 42
   [2 1 1]
   [4 6 112 117 98 105 99]
   [-94 29
    [2 4 124 -67 ....]
    [48 13
     [6 8 43 6 1 ...]
     [2 1 88]]]]

  (snmp-message?
    (bytes->tlv-structure sysServices))
  (decode-ber-bytes sysServices)

  ;; integer 10250, tag 2, length 2 value [28 0x0a]
  (decode-length [02 02 28 0x0A])
  ;;=> [2 (2 28 10)]

  (decode-timeticks [62 41 112])

  (decode-unsigned-integer [95 120 71])                ;; 6256711
  (decode-integer [5 -96])
  (decode-unsigned-integer [5 -96])
  (decode-integer [42 81 -116 117])
  (bit-and 0x02 0xFF)

  (u/->hex-str 66)
  (rest
    (second
      (decode-length
        [48 60
         2 1 1
         4 6 112 117 98 108 105 99
         -94 47 2 4 125 73 104 -62 2 1 0 2 1 0
         48 33 48 13 6 8 43 6 1 2 1 1 7 0 2 1 88
         48 16 6 8 43 6 1 2 1 1 3 0 67 4 0 -38 71 10])))
  (decode-integer [0x81 0x8f])

  )

