(ns kouvas.snmp4clj.smi.ip-address
  (:require [kouvas.snmp4clj.variable :as p]
            [kouvas.snmp4clj.ber :as ber])
  (:import (java.net InetAddress)))

(def ^:private any-ip-address-bytes (byte-array [0 0 0 0]))

(defrecord IpAddress [inet-address type])

(extend IpAddress
  p/Variable
  p/default-variable-behaviour

  ber/BERSerializable
  {:encode-ber (fn [this] (ber/encode-ip-address this))})


(defn make-ip-address
  ([]
   (make-ip-address nil any-ip-address-bytes))
  ([^String host]
   (let [address (InetAddress/getByName host)]
     (->IpAddress address :ber/ip-address)))
  ([^String host ^bytes addr-bytes]
   (->IpAddress (InetAddress/getByAddress host addr-bytes) :ber/ip-address)))


(comment

  (def ip
    (make-ip-address "192.167.7.7"))
  (ber/encode-ber ip)
  (ber/decode-ber (ber/encode-ber ip))
  )


