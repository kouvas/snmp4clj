(ns kouvas.snmp4clj.target
  (:require [kouvas.snmp4clj.smi.ip-address :as ip]))

;; https://www.rfc-editor.org/rfc/rfc3411.html#page-30 todo

(defrecord Target [address port version timeout retries transport
                   security-level security-model security-name max-size-request-pdu])

(defn make-target
  [host port version community timeout retries transport max-size-request-pdu security-level security-model]
  (let [ip-address (ip/make-ip-address host)]
    (->Target ip-address port version timeout retries transport security-level security-model community max-size-request-pdu)))


