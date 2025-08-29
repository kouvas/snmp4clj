"
Opaque represents the SMI type Opaque which is used
to transparently exchange BER encoded values.

Opaque data type is a SMIv2 data type that can hold any binary
data, regardless of its format or meaning. It is encoded as an
ASN. 1 OCTET STRING, which is a sequence of 8-bit bytes.
Opaque data type is useful when there is no suitable SMIv2 data
type to represent the information that needs to be conveyed by SNMP.
"

(ns kouvas.snmp4clj.smi.opaque
  (:require [kouvas.snmp4clj.ber :as ber])
  (:import (kouvas.snmp4clj.ber BERSerializable)))


(defrecord Opaque [value type])

(extend Opaque
  BERSerializable
  {:encode-ber (fn [this] (ber/encode-opague this))})

(defn make-opague
  ([]
   (make-opague (byte-array 0) :ber/opaque))
  ([byte-array type]
   (Opaque. byte-array type)))

