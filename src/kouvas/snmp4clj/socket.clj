(ns kouvas.snmp4clj.socket
  (:refer-clojure :exclude [send])
  (:require [kouvas.snmp4clj.packet :as packet]
            [kouvas.snmp4clj.tags :as t])
  (:import (java.net DatagramPacket DatagramSocket InetAddress)))


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
  ([] (create 5000))
  ([timeout]
   (doto (DatagramSocket.)
     (timeout! timeout))))

;; ----------------------------------------------------------------------------
;; Protocol Extensions

(extend DatagramSocket
  Socket
  implementation)

(defn send-bytes
  [bytes port]
  (try
    (with-open [^DatagramSocket socket (create)]
      (let [send-buffer bytes
            address     (InetAddress/getLocalHost)
            send-packet (packet/create send-buffer address port)]
        (timeout! socket 5000)
        (send socket send-packet)
        (let [receive-buffer (byte-array 1024)
              receive-packet (packet/create receive-buffer address port)]
          (receive socket receive-packet)
          (let [length (packet/length receive-packet)
                result (byte-array length)]
            (System/arraycopy receive-buffer 0 result 0 length)
            result))))
    (catch java.net.SocketTimeoutException _
      (println "No response from server"))
    (catch Exception e
      (println "Error communicating with server:" (.getMessage e)))))

(comment

  (defn start-echo-server [port]
    (future
      (with-open [^DatagramSocket socket (create (int port))]
        (timeout! socket 1000)
        (println "Echo server started on port " port)
        ;; continuously run on a new thread/future, until interrupted
        ;; another way to loop https://github.com/weavejester/teensyp/blob/master/src/teensyp/server.clj#L169-L176
        (while (not (Thread/interrupted))
          (try
            (let [buf                    (byte-array 256)
                  ^DatagramPacket packet (packet/create buf)]
              (receive socket packet)
              (let [^String received (String/new buf 0 (.getLength packet))]
                (println "Received: " received)
                (send socket packet)
                (when (= received "end")
                  (.interrupt (Thread/currentThread)))))
            (catch java.net.SocketTimeoutException _
              (println "timeout, normal, continue?"))))
        (println "Echo server stopped"))))

  (defn send-msg
    [^String msg port]
    (let [socket      (create)
          send-buffer (.getBytes msg)
          address     (InetAddress/getLocalHost)
          send-packet (packet/create send-buffer address port)]
      ;; set timeout or it will block forever if server has gone wrong or was stopped
      ;;(println send-buffer)
      (timeout! socket 5000)                           ; increase timeout and reply from nc process
      (send socket send-packet)
      (let [receive-buffer (byte-array 1024)
            receive-packet (packet/create receive-buffer address port)]
        (try
          (receive socket receive-packet)
          (String. receive-buffer 0 (packet/length receive-packet))
          (catch java.net.SocketTimeoutException _
            (println "No response from server")
            nil)
          (finally
            (.close ^DatagramSocket socket))))))

  (def future-server (start-echo-server 7777))
  (send-msg "what??" 5161)
  (send-msg "end" 7777)
  (future-cancel future-server)
  (future-cancelled? future-server)
  (+ 1 1)
  (type future-server)

  (def sysUptime [0x06 0x08 0x2b 0x06 0x01 0x02 0x01 0x01 0x03 0x00])
  (def sysDescr [0x06 0x08 0x2b 0x06 0x01 0x02 0x01 0x01 0x01 0x00])

  (def hex-bytes (byte-array
                   [0x30 0x29                          ; SEQUENCE, length 41 bytes (SNMP message)
                    0x02 0x01 0x01                     ; INTEGER 1 (SNMP version - SNMPv2c)
                    0x04 0x06 0x70 0x75 0x62 0x6c 0x69 0x63 ; OCTET STRING "public" (community string)
                    0xa0 0x1c                          ; GetRequest PDU, length 28 bytes
                    0x02 0x04 0x0b 0x35 0xf2 0x22      ; INTEGER request-id (0x0b35f222 = 188019234)
                    0x02 0x01 0x00                     ; INTEGER error-status (0 = no error)
                    0x02 0x01 0x00                     ; INTEGER error-index (0)
                    0x30 0x0e                          ; SEQUENCE varbind list, length 14
                    0x30 0x0c                          ; SEQUENCE varbind, length 12
                    0x06 0x08 0x2b 0x06 0x01 0x02 0x01 0x01 0x01 0x00 ; OID 1.3.6.1.2.1.1.1.0 (sysDescr.0)
                    0x05 0x00                          ; NULL (for GetRequest)
                    ]))
  ;; Full message as decimal bytes:
  (def dec-bytes (byte-array [48 41                    ; SEQUENCE (48/0x30), length 41
                              2 1 1                    ; tag type, length, INTEGER 1 (version)
                              4 6 112 117 98 108 105 99 ; tag type, length, OCTET STRING "public"
                              160 28                   ; GetRequest PDU (160 = 0xa0)
                              2 4 11 53 242 34         ; INTEGER request-id
                              2 1 0                    ; INTEGER error-status
                              2 1 0                    ; INTEGER error-index
                              48 14                    ; SEQUENCE varbind list
                              48 12                    ; SEQUENCE varbind
                              6 8
                              43 6 1 2 1 1 6 0
                              ;;43 6 1 2 1 1 1 0     ; OID
                              5 0]))                   ; NULL

  (int 0x30)
  (map byte
       sysUptime)
  (send-bytes dec-bytes 5161)
  (def result (send-bytes dec-bytes 5161))
  (vec (.getBytes result))
  (vec (.getBytes "Server Room"))

  (int 0x1c)
  (char 0x70)
  (java.util.Arrays/equals
    (byte-array [0xa0])
    (byte-array [(unchecked-byte (:pdu/get t/pdu))]))

  (int 0x30)
  (int (:ber/sequence t/ber)))

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
;;
;;