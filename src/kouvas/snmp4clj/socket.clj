(ns kouvas.snmp4clj.socket
  (:refer-clojure :exclude [send])
  (:require [kouvas.snmp4clj.packet :as packet])
  (:import (java.net DatagramPacket DatagramSocket InetAddress)))

(set! *warn-on-reflection* true)

;; ----------------------------------------------------------------------------
;; Protocols

(defprotocol Socket
  (send [this packet] "Sends a datagram packet from this socket")
  (receive [this packet]
    "Receives a datagram packet from this socket")
  (timeout! [this timeout] "Set timeout for socket")
  (close [this] "Closes this datagram socket")
  (port [this] "Returns the port of this socket")
  (open? [this] "Returns true if socket is not closed"))

;; ----------------------------------------------------------------------------
;; Implementation

(def implementation
  {:send     (fn [^DatagramSocket this ^DatagramPacket packet]
               (.send this packet))
   :timeout! (fn [^DatagramSocket this ^long timeout]
               (.setSoTimeout this timeout))
   :receive  (fn [^DatagramSocket this ^DatagramPacket packet]
               (.receive this packet))
   :close    (fn [^DatagramSocket this]
               (.close this))
   :port     (fn [^DatagramSocket this]
               (.getLocalPort this))
   :open?    (fn [^DatagramSocket this]
               (not (.isClosed this)))})

;; ----------------------------------------------------------------------------
;; Constructors

(defn create
  ([] (DatagramSocket/new))
  ([port] (^[int] DatagramSocket/new port)))

;; ----------------------------------------------------------------------------
;; Protocol Extensions

(extend DatagramSocket
  Socket
  implementation)

;; ----------------------------------------------------------------------------
;; Utils / Helpers

(defn bytes->hex-str [bytes]
  (apply str (map #(format "%02x " (bit-and % 0xff)) bytes)))



(comment

  (defn send-bytes
    [bytes-a port]
    (let [socket      (create)
          send-buffer bytes-a
          address     (InetAddress/getLocalHost)
          send-packet (packet/create send-buffer address port)]
      ;; set timeout or it will block forever if server has gone wrong or was stopped
      ;;(println send-buffer)
      (timeout! socket 5000)                                ; increase timeout and reply from nc process
      (send socket send-packet)
      (let [receive-buffer (byte-array 1024)
            receive-packet (packet/create receive-buffer address port)]
        (try
          (receive socket receive-packet)
          (^[byte/1 int int] String/new receive-buffer 0 (packet/length receive-packet))
          (catch java.net.SocketTimeoutException _
            (println "No response from server")
            nil)
          (finally
            (close socket))))))

  (def hex-bytes (byte-array
                   [0x30 0x29                               ; SEQUENCE, length 41 bytes (SNMP message)
                    0x02 0x01 0x01                          ; INTEGER 1 (SNMP version - SNMPv2c)
                    0x04 0x06 0x70 0x75 0x62 0x6c 0x69 0x63 ; OCTET STRING "public" (community string)
                    0xa0 0x1c                               ; GetRequest PDU, length 28 bytes
                    0x02 0x04 0x0b 0x35 0xf2 0x22           ; INTEGER request-id (0x0b35f222 = 188019234)
                    0x02 0x01 0x00                          ; INTEGER error-status (0 = no error)
                    0x02 0x01 0x00                          ; INTEGER error-index (0)
                    0x30 0x0e                               ; SEQUENCE varbind list, length 14
                    0x30 0x0c                               ; SEQUENCE varbind, length 12
                    0x06 0x08 0x2b 0x06 0x01 0x02 0x01 0x01 0x01 0x00 ; OID 1.3.6.1.2.1.1.1.0 (sysDescr.0)
                    0x05 0x00                               ; NULL (for GetRequest)
                    ]))

  (send-bytes hex-bytes 5161)
  )