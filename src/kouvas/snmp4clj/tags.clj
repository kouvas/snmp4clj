(ns kouvas.snmp4clj.tags)

(def ^:const minimum-pdu-length 484)                   ; const will also type hint at comp time
(def ^:const default-command-responder-port 161)
(def ^:const supported-transport-protocols #{:udp})
(def ^:const default-transport :udp)

;; ============================================================================
;; ASN.1 Constants
;; ============================================================================

;; ASN.1 Class constants
(def ^:const asn1-universal 0x00)
(def ^:const asn1-application 0x40)
(def ^:const asn1-context (unchecked-byte 0x80))
(def ^:const asn1-private (unchecked-byte 0xC0))

;; ASN.1 Tag form constants
(def ^:const asn1-primitive (unchecked-byte 0x00))
(def ^:const asn1-constructor (unchecked-byte 0x20))

;; ASN.1 Length encoding form constants
(def ^:const asn1-short-form 0x01)
(def ^:const asn1-long-form 0x02)

;; ASN.1 Special value constants
(def ^:const asn1-long-length (unchecked-byte 0x80))
(def ^:const asn1-extension-id (unchecked-byte 0x1F))
(def ^:const asn1-bit8 (unchecked-byte 0x80))

;; ASN.1 Basic and structured data type constants
(def ^:const asn1-boolean 0x01)
(def ^:const asn1-integer 0x02)
(def ^:const asn1-bit-str 0x03)
(def ^:const asn1-octet-str 0x04)
(def ^:const asn1-null 0x05)
(def ^:const asn1-object-id 0x06)
(def ^:const asn1-sequence 0x10)
(def ^:const asn1-set 0x11)

;; ============================================================================
;; BER Constants
;; ============================================================================

(def ^:constant ber
  {;; BER Data types (combining ASN.1 class and type)
   :ber/integer                (bit-or asn1-universal 0x02)
   :ber/integer32              (bit-or asn1-universal 0x02)
   ;; The BIT STRING type has been temporarily defined in RFC 1442
   ;; and obsoleted by RFC 2578. Use OctetString
   :ber/bit-str                (bit-or asn1-universal 0x03)
   :ber/octet-string           (bit-or asn1-universal 0x04)
   :ber/null                   (bit-or asn1-universal 0x05)
   :ber/oid                    (bit-or asn1-universal 0x06)
   :ber/ip-address             (bit-or asn1-application 0x00)
   :ber/counter32              (bit-or asn1-application 0x01)
   :ber/gauge32                (bit-or asn1-application 0x02)
   :ber/timeticks              (bit-or asn1-application 0x03)
   :ber/opaque                 (bit-or asn1-application 0x04)
   :ber/counter64              (bit-or asn1-application 0x06)
   :ber/sequence               (bit-or asn1-constructor 0x10)

   ;; BER exception values
   :ber/no-such-object         (int 0x80)
   :ber/no-such-instance       (int 0x81)
   :ber/end-of-mib-view        (int 0x82)

   ;; BER Processing constants
   :ber/lenmask                0x0ff                   ;; mask lower 8 bits
   :ber/max-oid-length         128

   ;; BER Validation flags
   :ber/check-sequence-length  true
   :ber/check-value-length     true
   :ber/check-first-sub-id-o12 true

   ;; Opaque special type constants
   :ber/opaque-subtype         0x9F                    ; ASN_OPAQUE_TAG1 (context | extension_id)
   :ber/opaque-float           0x78                    ; ASN_OPAQUE_FLOAT (120)
   :ber/opaque-double          0x79                    ; ASN_OPAQUE_DOUBLE (121)
   :ber/opaque-int64           0x7A                    ; ASN_OPAQUE_I64 (122)
   :ber/opaque-uint64          0x7B                    ; ASN_OPAQUE_U64 (123)

   ;; BER length constants for Opaque special types
   :ber/opaque-float-len       7                       ; ASN_OPAQUE_FLOAT_BER_LEN
   :ber/opaque-double-len      11                      ; ASN_OPAQUE_DOUBLE_BER_LEN
   :ber/opaque-int64-max-len   11                      ; ASN_OPAQUE_I64_MX_BER_LEN
   :ber/opaque-uint64-max-len  12                      ; ASN_OPAQUE_U64_MX_BER_LEN
   })

(def ^:const smi
  {:syntax/integer           asn1-integer
   :syntax/integer32         asn1-integer
   :syntax/unsigned-int32    (:ber/gauge32 ber)
   :syntax/octet-string      asn1-octet-str
   :syntax/null              asn1-null
   :syntax/object-identifier asn1-object-id
   :syntax/ip-address        (:ber/ip-address ber)
   :syntax/counter32         (:ber/counter32 ber)
   :syntax/gauge32           (:ber/gauge32 ber)
   :syntax/timeticks         (:ber/timeticks ber)
   :syntax/opaque            (:ber/opaque ber)
   :syntax/counter64         (:ber/counter64 ber)
   :syntax/bits              asn1-octet-str
   ;; exception types, context-specific
   :syntax/no-such-object    (:ber/no-such-object ber)
   :syntax/no-such-instance  (:ber/no-such-instance ber)
   :syntax/end-of-mib-view   (:ber/end-of-mib-view ber)})

(def ^:const pdu
  {:get      (bit-or asn1-context asn1-constructor)
   :get-next (bit-or asn1-context asn1-constructor 0x1)
   :trap-v1  (bit-or asn1-context asn1-constructor 0x04)
   :set      (bit-or asn1-context asn1-constructor 0x03)
   ;; additional for v2c
   :response (bit-or asn1-context asn1-constructor 0x2)
   :get-bulk (bit-or asn1-context asn1-constructor 0x05)
   :inform   (bit-or asn1-context asn1-constructor 0x06)
   :trap     (bit-or asn1-context asn1-constructor 0x7)
   :report   (bit-or asn1-context asn1-constructor 0x8)})

(def ^:const errors
  {;; SNMP error codes
   :error/timeout                 -1
   :error/lexicographic-order     -2
   :error/report                  -3
   :error/io                      -4

   ;; SNMP protocol-defined error codes
   :error/success                 0
   :error/too-big                 1
   :error/no-such-name            2
   :error/bad-value               3
   :error/read-only               4
   :error/general-error           5
   :error/no-access               6
   :error/wrong-type              7
   :error/wrong-length            8
   :error/wrong-encoding          9
   :error/wrong-value             10
   :error/no-creation             11
   :error/inconsistent-value      12
   :error/resource-unavailable    13
   :error/commit-failed           14
   :error/undo-failed             15
   :error/authorization-error     16
   :error/not-writeable           17
   :error/inconsistent-name       18

   ;; Message Processing (MP) codes
   :mp/ok                         0
   :mp/error                      -1400
   :mp/unsupported-security-model -1402
   :mp/not-in-time-window         -1403
   :mp/doubled-message            -1404
   :mp/invalid-message            -1405
   :mp/invalid-engineid           -1406
   :mp/not-initialized            -1407
   :mp/parse-error                -1408
   :mp/unknown-msgid              -1409
   :mp/match-error                -1410
   :mp/community-error            -1411
   :mp/wrong-user-name            -1412
   :mp/build-error                -1413
   :mp/usm-error                  -1414
   :mp/unknown-pdu-handlers       -1415
   :mp/unavailable-context        -1416
   :mp/unknown-context            -1417
   :mp/report-sent                -1418

   ;; SNMPv1v2c Community Security Model codes
   :csm/ok                        0
   :csm/bad-community-name        1501
   :csm/bad-community-use         1502})

(def ^:constant syntax-name-mapping
  {"BIT STRING"        :ber/bit-str
   ;; integer32 used only in syntax-name-mapping and getSyntaxFromString()
   "Integer32"         :ber/integer32
   "OCTET STRING"      :ber/octet-str
   "OBJECT IDENTIFIER" :ber/oid
   "TimeTicks"         :ber/timeticks
   "Counter"           :ber/counter
   "Counter64"         :ber/counter64
   "EndOfMibView"      :ber/end-of-mib-view
   "Gauge"             :ber/gauge32
   "Unsigned32"        :ber/gauge32
   "IpAddress"         :ber/ip-address
   "NoSuchInstance"    :ber/no-such-instance
   "NoSuchObject"      :ber/no-such-object
   "Null"              :ber/null
   "Opaque"            :ber/opaque})

(defn ->syntax-str
  "Returns textual description of the supplied (BER code) syntax type"
  [syntax]
  (case syntax
    :ber/integer "Integer32"
    :ber/bit-str "BIT STRING"
    :ber/octet-str "OCTET STRING"
    :ber/oid "OBJECT IDENTIFIER"
    :ber/timeticks "TimeTicks"
    :ber/counter "Counter"
    :ber/counter64 "Counter64"
    :ber/gauge32 "Gauge"
    :ber/ip-address "IpAddress"
    :ber/null "Null"
    :ber/no-such-object "noSuchObject"
    :ber/no-such-instance "noSuchInstance"
    :ber/end-of-mib-view "endOfMibView"
    :ber/opaque "Opaque"
    "?"))

(comment
  (int 0x1c)
  (char 0x70)
  (java.util.Arrays/equals
    (byte-array [0xa0])
    (byte-array [(unchecked-byte (:pdu/get pdu))]))

  (int 0x30)
  (int (:ber/sequence ber))

  (defn hex-byte-to-binary [hex-str]
    (format "%08d" (Integer/parseInt (Integer/toBinaryString (Integer/parseInt hex-str 16)))))

  ; 30 29                                   ; SEQUENCE, length 41 bytes (SNMP message)
  ;;  02 01 01                              ; INTEGER 1 (SNMP version - SNMPv2c)
  ;;  04 06 70 75 62 6c 69 63               ; OCTET STRING "public" (community string)
  ;;   a0 1c                                ; GetRequest PDU (a0: -96 unchecked), length 28 bytes
  ;;     02 04 0b 35 f2 22                  ; INTEGER request-id (0x0b35f222 = 188019234)
  ;;     02 01 00                           ; INTEGER error-status (0 = no error)
  ;;     02 01 00                           ; INTEGER error-index (0)
  ;;     30 0e                              ; SEQUENCE varbind list, length 14
  ;;       30 0c                            ; SEQUENCE varbind, length 12
  ;;         06 08 2b 06 01 02 01 01 01 00  ; OID 1.3.6.1.2.1.1.1.0 (sysDescr.0)
  ;;         05 00                          ; NULL (for GetRequest))

  ;; bit 7-6: 00 = Universal class, standard asn.1 type
  ;; bit 5: 1    = Constructed, contains other encoded values
  ;; bits 4-0: 10000 = Tag number 16(sequence)
  ;;This SEQUENCE contains the entire SNMP message structure:
  ;;
  ;;SNMP version (3 bytes)
  ;;Community string (8 bytes)
  ;;PDU (30 bytes)
  ;;
  ;;Total: 3 + 8 + 30 = 41 bytes, which matches the 29 length indicator.
  ;;In ASN.1/BER encoding, SEQUENCE is used to group related data elements together, similar to a struct or record in programming languages.

  (hex-byte-to-binary "2b")
  (unchecked-byte 0x2b))

(comment
  (:ber/sequence ber)

  (:get pdu)
  (unchecked-byte
    0xa0)

  (let [tag 0x02]
    (case (bit-and tag 0xFF)
      (get ber :ber/integer) :integer
      0x04 :string
      :none)))