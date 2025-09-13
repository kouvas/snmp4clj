(ns kouvas.snmp4clj.variable
  (:require [kouvas.snmp4clj.tags :as t]))

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
