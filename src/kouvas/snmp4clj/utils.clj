(ns kouvas.snmp4clj.utils)

;; -----------------------------
;; Bytes
;; -----------------------------

(defn int->byte
  [n]
  (unchecked-byte n))

(defn hex-string->dec-byte
  "Converts a hexadecimal string to it's corresponding decimal byte value.
  Bytes in Clojure are signed (-128 to 127) so\n   when a byte value is
  greater than 127 it wraps around to negative

  Accepts strings in formats: '0x02', '02', '2', 'A5', etc.
  Returns a byte value. "
  [hex-str]
  (let [cleaned-hex (if (.startsWith hex-str "0x")
                      (subs hex-str 2)
                      hex-str)]
    (unchecked-byte (Long/parseLong cleaned-hex 16))))

(defn ->hex-str
  "Converts a byte to its hexadecimal string representation.
  Returns a string in the format '0xNN' where NN is the two-digit hex value.
  Handles Java's signed bytes correctly (e.g., -1 becomes '0xFF')."
  [b]
  (format "0x%02X" (bit-and b 0xFF)))

(defn signed->unsigned
  [n]
  (bit-and n 0xFF))