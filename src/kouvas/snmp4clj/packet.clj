(ns kouvas.snmp4clj.packet
  (:import (java.net DatagramPacket InetAddress)))


;; ----------------------------------------------------------------------------
;; Constants

(def ^:const default-packet-size (int 1024))

;; ----------------------------------------------------------------------------
;; Protocols

(defprotocol Packet
  (data [this] "Returns the data buffer")
  (length [this] "Returns the length of the data")
  (offset [this] "Returns the offset of the data")
  (address [this] "Returns the IP address")
  (port [this] "Returns the port number")
  (set-data! [this buffer] "Sets the data buffer")
  (set-length! [this length] "Sets the length")
  (set-address! [this address] "Sets the IP address")
  (set-port! [this port] "Sets the port number"))

;; ----------------------------------------------------------------------------
;; Implementation

(def implementation
  {:data         (fn [^DatagramPacket this]
                   (.getData this))
   :length       (fn [^DatagramPacket this]
                   (.getLength this))
   :offset       (fn [^DatagramPacket this]
                   (.getOffset this))
   :address      (fn [^DatagramPacket this]
                   (.getAddress this))
   :port         (fn [^DatagramPacket this]
                   (.getPort this))
   :set-data!    (fn [^DatagramPacket this ^bytes buffer]
                   (.setData this buffer)
                   this)
   :set-length!  (fn [^DatagramPacket this length]
                   (.setLength this (int length))
                   this)
   :set-address! (fn [^DatagramPacket this ^InetAddress address]
                   (.setAddress this address)
                   this)
   :set-port!    (fn [^DatagramPacket this port]
                   (.setPort this (int port))
                   this)})

;; ----------------------------------------------------------------------------
;; Constructors

(defn create
  "Creates a DatagramPacket"
  ([]
   (let [buffer (byte-array default-packet-size)]
     (DatagramPacket. buffer (alength buffer))))
  ([^bytes buffer]
   (DatagramPacket. buffer (alength buffer)))
  ([^bytes buffer length]
   (DatagramPacket. buffer (int length)))
  ([^bytes buffer ^InetAddress address port]
   (DatagramPacket. buffer (alength buffer) address (int port)))
  ([^bytes buffer offset length ^InetAddress address port]
   (DatagramPacket. buffer (int offset) (int length) address (int port))))

;; ----------------------------------------------------------------------------
;; Protocol Extensions

(extend DatagramPacket
  Packet
  implementation)

;; ----------------------------------------------------------------------------
;; Utils / Helpers

(defn data->string
  "Converts the packet's data to a string"
  ([this]
   (let [^bytes d (data this)]
     (String. d (int (offset this)) (int (length this)))))
  ([this ^String encoding]
   (let [^bytes d (data this)]
     (String. d (int (offset this)) (int (length this)) encoding))))

(defn reset-length!
  "Resets the length of the packet to the length of its buffer"
  [this]
  (let [^bytes d (data this)]
    (set-length! this (alength d))))