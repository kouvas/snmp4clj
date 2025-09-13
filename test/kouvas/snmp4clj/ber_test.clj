(ns kouvas.snmp4clj.ber-test
  "BER encoding/decoding function tests - focused on low-level BER operations."
  (:require [clojure.test :refer :all]
            [kouvas.snmp4clj.ber :as ber]
            [kouvas.snmp4clj.smi.counter32 :as c32]
            [kouvas.snmp4clj.smi.integer32 :as i32]
            [kouvas.snmp4clj.smi.ip-address :as ip]
            [kouvas.snmp4clj.smi.octet-string :as os]
            [kouvas.snmp4clj.tags :as c]))

(deftest encode-length-test
  (testing "Encoding of the length that represents the size of bytes array of an encoded value"
    (is (= [4] (ber/encode-length 4)))
    (is (= [-127 -1] (ber/encode-length 255)))
    (is (= [-124 127 -1 -1 -1] (ber/encode-length Integer/MAX_VALUE)))))

(deftest encode-integer-test
  (let [tag-byte            (byte (:ber/integer c/ber))
        byte-of-dec-127     (byte 0x7F)
        byte-of-dec-255     (unchecked-byte 0xFF)
        byte-of-dec-neg-1   (unchecked-byte 0xFF)
        byte-of-dec-neg-128 (unchecked-byte 0x80)
        byte-of-dec-0       (byte 0x00)
        padding-byte        (byte 0x00)]

    (testing "encode positive integers 127 and 255"
      (is (= [tag-byte 1 byte-of-dec-127]
             (ber/encode-ber (i32/make-integer32 127))))
      (is (= [tag-byte 2 padding-byte byte-of-dec-255]
             (ber/encode-ber (i32/make-integer32 255)))))

    (testing "encode negative integer"
      (is (= [tag-byte 1 byte-of-dec-neg-1]
             (ber/encode-ber (i32/make-integer32 -1)))) ;; neg number treat as signed -128 to 127
      (is (= [tag-byte 1 byte-of-dec-neg-128]
             (ber/encode-ber (i32/make-integer32 -128)))))

    (testing "encode max integer"
      (is (= [tag-byte 4 127 -1 -1 -1]
             (ber/encode-ber (i32/make-integer32 Integer/MAX_VALUE)))))

    (testing "encode zero"
      (is (= [tag-byte 1 byte-of-dec-0]
             (ber/encode-ber (i32/make-integer32 0)))))))

(deftest encode-unsigned-integer-test
  (testing "encode unsigned integers"
    (let [;; Test case 1: 0xFFFFFFFF (4294967295) - maximum 32-bit unsigned
          counter1  (c32/make-counter32 0xFFFFFFFF)
          encoded1  (ber/encode-ber counter1)
          ;; Expected: tag=0x41, length=5, padding=0x00, value=[0xFF 0xFF 0xFF 0xFF]
          expected1 [(byte 0x41) 5 (byte 0x00) (unchecked-byte 0xFF) (unchecked-byte 0xFF) (unchecked-byte 0xFF)
                     (unchecked-byte 0xFF)]

          ;; Test case 2: 0x7FFFFFFF (2147483647) - no padding needed
          counter2  (c32/make-counter32 0x7FFFFFFF)
          encoded2  (ber/encode-ber counter2)
          ;; Expected: tag=0x41, length=4, value=[0x7F 0xFF 0xFF 0xFF]
          expected2 [(byte 0x41) 4 (byte 0x7F) (unchecked-byte 0xFF) (unchecked-byte 0xFF) (unchecked-byte 0xFF)]]

      (is (= expected1 encoded1) "0xFFFFFFFF should encode with padding byte")
      (is (= expected2 encoded2) "0x7FFFFFFF should encode without padding")))

  (testing "encode unsigned integers - additional edge cases"
    (let [counter0  (c32/make-counter32 0)
          encoded0  (ber/encode-ber counter0)
          expected0 [(byte 0x41) 1 (byte 0x00)]

          counter3  (c32/make-counter32 0x80000000)
          encoded3  (ber/encode-ber counter3)
          expected3 [(byte 0x41) 5 (byte 0x00) (unchecked-byte 0x80) (byte 0x00) (byte 0x00) (byte 0x00)]

          counter4  (c32/make-counter32 255)
          encoded4  (ber/encode-ber counter4)
          expected4 [(byte 0x41) 2 (byte 0x00) (unchecked-byte 0xFF)]]

      (is (= expected0 encoded0) "Zero should encode as single zero byte")
      (is (= expected3 encoded3) "0x80000000 should encode with padding byte")
      (is (= expected4 encoded4) "255 should encode as single byte without padding"))))

(deftest decode-integer-test
  (testing "decoding an integer from BER encoded bytes"
    (let [value       188084770
          int32       (i32/make-integer32 value)
          bytes       (ber/encode-ber int32)
          ; Extract just the value bytes (skip tag and length)
          value-bytes (drop 2 bytes)
          decoded     (ber/decode-integer value-bytes)]
      (is (= value decoded)))))

(deftest encode-octet-string-test
  (let [tag-byte (:ber/octet-string c/ber)
        byte-h   0x68
        byte-e   0x65
        byte-l   0x6C
        byte-o   0x6F]

    (testing "encode ASCII string"
      (is (= [tag-byte 0x05 byte-h byte-e byte-l byte-l byte-o]
             (ber/encode-ber (os/make-octet-string "hello")))))

    (testing "encode empty string"
      (is (= [tag-byte 0]
             (ber/encode-ber (os/make-octet-string "")))))

    (testing "encode byte array"
      (is (= [tag-byte 3 0x01 0x02 0x03]
             (ber/encode-ber (os/make-octet-string (byte-array [1 2 3]))))))))

(deftest octet-str-round-trip-test
  (testing "Encode and decode round trip"
    (let [test-strings ["hello"
                        ""
                        "Hello SNMP4CLJ"
                        (apply str (repeat 100 "X"))
                        "Special chars: àáâãä"
                        "Binary data: \u0000\u0001\u00FF"]]
      (doseq [test-str test-strings]
        (testing (str "Round trip for: " (pr-str test-str))
          (let [original (os/make-octet-string test-str)
                encoded  (ber/encode-ber original)
                decoded  (ber/decode-ber encoded)]
            (is (= test-str decoded))))))))

(deftest decode-unsigned-integer-test
  (testing "decode unsigned integers from value bytes"
    (let [value1-bytes [(unchecked-byte 0xFF)]
          decoded1     (ber/decode-unsigned-integer value1-bytes)

          value2-bytes [(byte 0x00)]
          decoded2     (ber/decode-unsigned-integer value2-bytes)

          ;; Test case 3: Max 32-bit unsigned (0xFFFFFFFF) with padding
          ;; Encoded as [0x00 0xFF 0xFF 0xFF 0xFF] - padding byte first
          value3-bytes [(byte 0x00) (unchecked-byte 0xFF) (unchecked-byte 0xFF)
                        (unchecked-byte 0xFF) (unchecked-byte 0xFF)]
          decoded3     (ber/decode-unsigned-integer value3-bytes)

          ;; Test case 4: No padding needed (0x7FFFFFFF)
          value4-bytes [(byte 0x7F) (unchecked-byte 0xFF) (unchecked-byte 0xFF) (unchecked-byte 0xFF)]
          decoded4     (ber/decode-unsigned-integer value4-bytes)

          ;; Test case 5: Two bytes with padding (0x8000) 
          value5-bytes [(byte 0x00) (unchecked-byte 0x80) (byte 0x00)]
          decoded5     (ber/decode-unsigned-integer value5-bytes)]

      (is (= 255 decoded1) "Should decode 0xFF as 255")
      (is (= 0 decoded2) "Should decode 0x00 as 0")
      (is (= 4294967295 decoded3) "Should decode max 32-bit unsigned with padding")
      (is (= 2147483647 decoded4) "Should decode 0x7FFFFFFF without padding")
      (is (= 32768 decoded5) "Should decode 0x8000 with padding")))

  (testing "decode unsigned integers - error cases"
    (is (thrown-with-msg?
          clojure.lang.ExceptionInfo
          #"Empty value bytes"
          (ber/decode-unsigned-integer [])))

    (is (thrown-with-msg?
          clojure.lang.ExceptionInfo
          #"Length greater than 5 bytes"
          (ber/decode-unsigned-integer (repeat 6 (byte 0x01)))))))

(deftest encode-unsigned-int64-test
  (testing "encode-unsigned-int64 BER function"
    (let [test-record {:value -3914541189257109063 :type :ber/counter64}
          encoded     (ber/encode-unsigned-int64 test-record)
          expected    [(byte 0x46) 9 0 (unchecked-byte 0xC9) (unchecked-byte 0xAC) (unchecked-byte 0xC1) (unchecked-byte 0x87)
                       0x4B (unchecked-byte 0xB1) (unchecked-byte 0xE1) (unchecked-byte 0xB9)]]
      (is (= expected encoded) "encode big negative number correctly"))

    (let [test-record {:value 3 :type :ber/counter64}
          encoded     (ber/encode-unsigned-int64 test-record)
          expected    [(byte 0x46) 1 3]]
      (is (= expected encoded) "Value 3 should encode to [0x46, 0x01, 0x03]"))

    (let [test-record {:value 16777217 :type :ber/counter64}
          encoded     (ber/encode-unsigned-int64 test-record)
          expected    [(byte 0x46) 4 1 0 0 1]]
      (is (= expected encoded) "Value 16777217 should encode to [0x46, 0x04, 0x01, 0x00, 0x00, 0x01]")))

  (testing "encode-unsigned-int64 BER function - edge cases"
    (let [test-record {:value 0 :type :ber/counter64}
          encoded     (ber/encode-unsigned-int64 test-record)]
      (is (= [(byte 0x46) 1 0] encoded) "Zero should encode correctly"))

    (let [test-record {:value Long/MAX_VALUE :type :ber/counter64}
          encoded     (ber/encode-unsigned-int64 test-record)]
      (is (= (byte 0x46) (first encoded)) "Tag should be 0x46")
      (is (= 8 (second encoded)) "Length should be 8 bytes for Long/MAX_VALUE"))

    ;; -1 (becomes max unsigned when decoded)
    (let [test-record {:value -1 :type :ber/counter64}
          encoded     (ber/encode-unsigned-int64 test-record)]
      (is (= (byte 0x46) (first encoded)) "Tag should be 0x46")
      (is (= 9 (second encoded)) "Length should be 9 bytes for -1")
      (is (= 0 (nth encoded 2)) "Should have leading zero byte"))))

(deftest decode-unsigned-int64-test
  (testing "decode-unsigned-int64 BER function - normal cases"
    ;; Test case 1: Zero
    (let [value-bytes [(byte 0x00)]
          decoded     (ber/decode-unsigned-int64 value-bytes)]
      (is (= 0 decoded) "Zero should decode correctly"))

    (let [value-bytes [3]                              ; From [0x46, 0x01, 0x03]
          decoded     (ber/decode-unsigned-int64 value-bytes)]
      (is (= 3 decoded) "Value 3 should decode correctly"))

    (let [value-bytes [0 (unchecked-byte 0xC9) (unchecked-byte 0xAC) (unchecked-byte 0xC1) (unchecked-byte 0x87)
                       0x4B (unchecked-byte 0xB1) (unchecked-byte 0xE1) (unchecked-byte 0xB9)]
          decoded     (ber/decode-unsigned-int64 value-bytes)]
      (is (= 14532202884452442553N decoded) "should decode to unsigned equivalent"))

    (let [value-bytes [(byte 127) (byte -1) (byte -1) (byte -1) (byte -1) (byte -1) (byte -1) (byte -1)]
          decoded     (ber/decode-unsigned-int64 value-bytes)]
      (is (= 9223372036854775807N decoded) "Long/MAX_VALUE should decode correctly")))

  (testing "decode-unsigned-int64 BER function - edge cases and errors"
    (let [value-bytes [(byte 0) (byte -1) (byte -1) (byte -1) (byte -1)
                       (byte -1) (byte -1) (byte -1) (byte -1)]
          decoded     (ber/decode-unsigned-int64 value-bytes)]
      (is (= 18446744073709551615N decoded) "Max unsigned 64-bit value (with leading zeros) should decode correctly"))

    (is (thrown-with-msg?
          clojure.lang.ExceptionInfo
          #"Empty value bytes"
          (ber/decode-unsigned-int64 [])))

    (is (thrown-with-msg?
          clojure.lang.ExceptionInfo
          #"Counter64 length too large"
          (ber/decode-unsigned-int64 (repeat 10 (byte 0x01)))))))
(deftest encode-ip-address-test
  (testing "encode IPv4 addresses to BER format"
    (let [ip-addr  (ip/make-ip-address "192.168.1.1")
          encoded  (ber/encode-ber ip-addr)
          expected [(byte 0x40) 4 (unchecked-byte 192) (unchecked-byte 168) 1 1]]
      (is (= expected encoded) "Should encode standard private IP"))

    (let [ip-addr  (ip/make-ip-address "127.0.0.1")
          encoded  (ber/encode-ber ip-addr)
          expected [(byte 0x40) 4 127 0 0 1]]
      (is (= expected encoded) "Should encode localhost"))

    (let [ip-addr  (ip/make-ip-address "255.255.255.255")
          encoded  (ber/encode-ber ip-addr)
          expected [(byte 0x40) 4 (unchecked-byte 255) (unchecked-byte 255) (unchecked-byte 255) (unchecked-byte 255)]]
      (is (= expected encoded) "Should encode broadcast address"))

    (let [ip-addr  (ip/make-ip-address "0.0.0.0")
          encoded  (ber/encode-ber ip-addr)
          expected [(byte 0x40) 4 0 0 0 0]]
      (is (= expected encoded) "Should encode zero address"))

    (let [ip-addr  (ip/make-ip-address "test" (byte-array [10 0 0 1]))
          encoded  (ber/encode-ber ip-addr)
          expected [(byte 0x40) 4 10 0 0 1]]
      (is (= expected encoded) "Should encode IP created with byte array")))

  (testing "encode IPv6 address error cases"
    (let [ipv6-addr (ip/make-ip-address "::1")]
      (is (thrown-with-msg?
            clojure.lang.ExceptionInfo
            #"IPv6 addresses not supported yet"
            (ber/encode-ber ipv6-addr))))))

(deftest decode-ip-address-test
  (testing "decode IP address from 4-byte sequences"
    (is (= "192.168.1.1"
           (ber/decode-ip-address [192 168 1 1]))
        "Should decode standard private IP")

    (is (= "127.0.0.1"
           (ber/decode-ip-address [127 0 0 1]))
        "Should decode localhost")

    (is (= "255.255.255.255"
           (ber/decode-ip-address [255 255 255 255]))
        "Should decode broadcast address")

    (is (= "0.0.0.0"
           (ber/decode-ip-address [0 0 0 0]))
        "Should decode zero address")

    (is (= "192.168.100.254"
           (ber/decode-ip-address [(unchecked-byte 192) (unchecked-byte 168) 100 (unchecked-byte 254)]))
        "Should handle bytes > 127 correctly"))

  (testing "decode IP address error cases"
    (is (thrown-with-msg?
          clojure.lang.ExceptionInfo
          #"IP address must be exactly 4 bytes"
          (ber/decode-ip-address [192 168 1])))

    (is (thrown-with-msg?
          clojure.lang.ExceptionInfo
          #"IP address must be exactly 4 bytes"
          (ber/decode-ip-address [192 168 1 1 1])))

    (is (thrown-with-msg?
          clojure.lang.ExceptionInfo
          #"IP address must be exactly 4 bytes"
          (ber/decode-ip-address [])))))

(deftest decode-netsnmp-double-test
  (testing "decode Net-SNMP double values from 8-byte sequences"
    (let [double-bytes [0x40 0x59 0x00 0x00 0x00 0x00 0x00 0x00]
          decoded      (ber/decode-opaque-double double-bytes)]
      (is (instance? Double decoded) "Should return a Double instance")
      (is (pos? decoded) "Should decode to positive value"))

    (let [double-bytes [0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00]
          decoded      (ber/decode-opaque-double double-bytes)]
      (is (= 0.0 decoded) "Should decode zero correctly"))

    (let [double-bytes [0x3F 0xBD 0xE6 0x3C 0x00 0x00 0x00 0x00]
          decoded      (ber/decode-opaque-double double-bytes)]
      (is (instance? Double decoded) "Should return a Double instance")))

  (testing "decode-netsnmp-double error cases"
    (is (thrown-with-msg?
          clojure.lang.ExceptionInfo
          #"Double must be exactly 8 bytes"
          (ber/decode-opaque-double [0x3F 0xBD 0xE6])))

    (is (thrown-with-msg?
          clojure.lang.ExceptionInfo
          #"Double must be exactly 8 bytes"
          (ber/decode-opaque-double [0x3F 0xBD 0xE6 0x3C 0x00 0x00 0x00 0x00 0x01])))

    (is (thrown-with-msg?
          clojure.lang.ExceptionInfo
          #"Double must be exactly 8 bytes"
          (ber/decode-opaque-double [])))))

(deftest decode-signed-int64-variable-test
  (testing "decode signed 64-bit integers with variable length"
    (let [int64-bytes [0x42]
          decoded     (ber/decode-opaque-signed-int64 int64-bytes)]
      (is (= 66 decoded) "Should decode single byte correctly"))

    (let [int64-bytes [0xFF]                           ; -1 in two's complement
          decoded     (ber/decode-opaque-signed-int64 int64-bytes)]
      (is (= -1 decoded) "Should decode negative single byte correctly"))

    (let [int64-bytes [0x7F 0xFF 0xFF 0xFF]            ; Max positive 32-bit
          decoded     (ber/decode-opaque-signed-int64 int64-bytes)]
      (is (= 2147483647 decoded) "Should decode max positive 32-bit value"))

    (let [int64-bytes [0x80 0x00 0x00 0x00]            ; Min negative 32-bit
          decoded     (ber/decode-opaque-signed-int64 int64-bytes)]
      (is (= -2147483648 decoded) "Should decode min negative 32-bit value"))

    (let [int64-bytes [0x7F 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF]
          decoded     (ber/decode-opaque-signed-int64 int64-bytes)]
      (is (= Long/MAX_VALUE decoded) "Should decode Long/MAX_VALUE"))

    (let [int64-bytes [0x00]
          decoded     (ber/decode-opaque-signed-int64 int64-bytes)]
      (is (= 0 decoded) "Should decode zero correctly")))

  (testing "decode-signed-int64-variable error cases"
    (is (thrown-with-msg?
          clojure.lang.ExceptionInfo
          #"Empty value bytes"
          (ber/decode-opaque-signed-int64 [])))

    (is (thrown-with-msg?
          clojure.lang.ExceptionInfo
          #"Signed int64 too large"
          (ber/decode-opaque-signed-int64 (repeat 9 0x01))))))

(deftest decode-opaque-test
  (testing "decode Net-SNMP Opaque special types"
    (let [opaque-bytes [0x9F 0x78 0x04 0x3F 0xBD 0xE6 0x3C] ; Float
          decoded      (ber/decode-opaque opaque-bytes)]
      (is (instance? Float decoded) "Should return a Float instance")
      (is (pos? decoded) "Should decode to positive float value"))

    (let [opaque-bytes [0x9F 0x79 0x08 0x40 0x59 0x00 0x00 0x00 0x00 0x00 0x00]
          decoded      (ber/decode-opaque opaque-bytes)]
      (is (instance? Double decoded) "Should return a Double instance"))

    (let [opaque-bytes [0x9F 0x7B 0x01 0x42]
          decoded      (ber/decode-opaque opaque-bytes)]
      (is (= 66 decoded) "Should decode UInt64 small value correctly"))

    (let [opaque-bytes [0x9F 0x7A 0x01 0xFF]           ; -1
          decoded      (ber/decode-opaque opaque-bytes)]
      (is (= -1 decoded) "Should decode Int64 negative value correctly"))

    (let [opaque-bytes [0x9F 0x7A 0x04 0x7F 0xFF 0xFF 0xFF]
          decoded      (ber/decode-opaque opaque-bytes)]
      (is (= 2147483647 decoded) "Should decode Int64 large positive value correctly")))

  (testing "decode opaque fallback to raw bytes"
    (let [opaque-bytes [0x9F 0x99 0x04 0x01 0x02 0x03 0x04] ; Unknown type 0x99
          decoded      (ber/decode-opaque opaque-bytes)]
      (is (= [-97 -103 4 1 2 3 4] (seq decoded)) "Should return full structure for unknown type"))

    (let [opaque-bytes [0x01 0x02 0x03 0x04]
          decoded      (ber/decode-opaque opaque-bytes)]
      (is (= [1 2 3 4] (seq decoded)) "Should return all bytes for non-special opaque")))

  (testing "decode opaque error and edge cases"
    (let [decoded (ber/decode-opaque [])]
      (is (nil? (seq decoded)) "Should return byte array that seq's to nil for empty input"))

    (let [opaque-bytes [0x9F 0x78]                     ; Float type but no length/data
          decoded      (ber/decode-opaque opaque-bytes)]
      (is (= [-97 120] (seq decoded)) "Should return raw bytes for truncated special type"))

    (let [opaque-bytes [0x9F 0x78 0x02 0x3F 0xBD]
          decoded      (ber/decode-opaque opaque-bytes)]
      (is (= [-97 120 2 63 -67] (seq decoded)) "Should return raw bytes for invalid float length"))

    (let [opaque-bytes [0x9F 0x79 0x04 0x40 0x59 0x00 0x00] ; Double with wrong length
          decoded      (ber/decode-opaque opaque-bytes)]
      (is (= [-97 121 4 64 89 0 0] (seq decoded)) "Should return raw bytes for invalid double length"))))