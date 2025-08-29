(ns kouvas.snmp4clj.variable
  (:require [kouvas.snmp4clj.tags :as t]))

;; combine methods from snmp4j's Variable interface, and AbstractVariable class
;; when inlining a protocol implementation in a record, make sure protocol methods do not
;; clash with default implement methods for all records like size of java.util.Map class
(defprotocol Variable
  "Protocol for all SMI variables"
  (to-string [this])
  (to-int [this])
  (to-long [this])
  (create-from-ber [this])
  (syntax [this]
    "Returns a string representation of the variable's value.")
  (snmp-exception? [this]))

(def default-variable-behaviour
  {:syntax (fn [this] (let [tag (:type this)] (t/->syntax-str tag)))})
