(in-package #:hwc)

(defparameter *nasdaq-itch-5.0-parser*
  `((module nasdaq-itch-parser "Extraction and parsing of Nasdaq ITCH 5.0 orders and trade related messages"
            :stream-in ethernet-input :stream-out command-out :frequency 322.265625e6)

    ;; The general interface
    (input uint32 (fpga-time "The FPGA time counter"))

    ;; The Ethernet AXI input stream interface
    (input uint32 ethernet-input-tdata)
    (input uint4 ethernet-input-tkeep)
    (input bit ethernet-input-tlast ethernet-input-tvalid)
    (output bit (ethernet-input-tready :special-use))

    ;; The commands AXI output stream interface
    (input bit command-out-tready)
    (output uint297 command-out-tdata)
    (output bit command-out-tvalid)

    ;; Let's register the inputs
    (setf ethernet-input-tlast (register ethernet-input-tlast))

    ;; Adding an extra clock cycle after the last word of each packet
    (change-execution (after-packet :exec-when ethernet-input-tlast))

    (setf (var bit start-of-packet) (falling-edge after-packet :initial-value 1))

    ;; The memory mapped registers interface
    (def-mmap-interface config-registers "The config/status registers" :data-width 32 :nb-words 8)

    (with-var-options (:interface config-registers)
      (input uint32 (nasdaq-ip-addr :untimed "The IP address of the incoming feed." :initial-value #.(ip32 233 54 12 101)))
      (input uint16 (nasdaq-udp-port :untimed "The IP port of the incoming feed." :initial-value 26400)))

    ;;The message parser takes the description of the messages and generates the hardware needed to decode them
    (def-message-parser2 parser :data-valid (bit.and (bit.not after-packet) ethernet-input-tvalid)
                                :sop start-of-packet :tkeep ethernet-input-tkeep :data-in ethernet-input-tdata
                                :protocol-desc
    (;; Ethernet header
       (dst-mac uint48)
       (src-mac uint48)
       (eth-type uint16)
    ;;IP header
       (version-and-IHL uint8)
       (DSCP-ECN uint8)
       (total-length uint16)
       (identification uint16)
       (flags-and-fragment-offset uint16)
       (time-to-live uint8)
       (protocol uint8)
       (header-checksum uint16)
       (ip-src-addr uint32)
       (ip-dest-addr uint32)
    ;; UDP header
       (udp-src-port int16)
       (udp-dest-port uint16)
       (udp-len uint16)
       (udp-checksum uint16)
    ;; MOLD header
       (mold-session uint64)
       (mold-session-msb uint16)
       (seqnum uint64)
       (msg-count uint16)
    ;; ITCH 5.0 Messages
       (:loop ((msg-length uint16) nil)
             (msg-type uint8)
             (:case (msg-type)
               (83 system-event-message ; S
                (locate uint16)
                (tracking uint16)
                (timestamp uint48)
                (event-code uint8))
               (72 stock-trading-action ; H
                (locate uint16)
                (tracking uint16)
                (timestamp uint48)
                (symbol uint64)
                (trading-state uint8))
               (89 reg-sho ; A
                (locate uint16)
                (tracking uint16)
                (timestamp uint48)
                (symbol uint64)
                (reg-sho-action uint8))
               (65 add-order ; A
                (locate uint16)
                (tracking uint16)
                (timestamp uint48)
                (order-ref-number uint64)
                (buy-sell uint8)
                (num-shares uint32)
                (symbol uint64)
                (price uint32))
               (70 add-order-with-mpid ; F
                (locate uint16)
                (tracking uint16)
                (timestamp uint48)
                (order-ref-number uint64)
                (buy-sell uint8)
                (num-shares uint32)
                (symbol uint64)
                (price uint32)
                (attribution uint32))
               (85 order-replace ; U
                (locate uint16)
                (tracking uint16)
                (timestamp uint48)
                (prev-order-ref-number uint64)
                (order-ref-number uint64)
                (num-shares uint32)
                (price uint32))
               (69 order-executed ; E
                (locate uint16)
                (tracking uint16)
                (timestamp uint48)
                (order-ref-number uint64)
                (num-shares uint32)
                (match-number uint64))
               (67 order-executed-with-price ; C
                (locate uint16)
                (tracking uint16)
                (timestamp uint48)
                (order-ref-number uint64)
                (num-shares uint32)
                (match-number uint64)
                (printable uint8)
                (price uint32))
               (88 order-cancel ; X
                (locate uint16)
                (tracking uint16)
                (timestamp uint48)
                (order-ref-number uint64)
                (num-shares uint32))
               (68 order-delete ; D
                (locate uint16)
                (tracking uint16)
                (timestamp uint48)
                (order-ref-number uint64))
               (80 trade ; P
                (locate uint16)
                (tracking uint16)
                (timestamp uint48)
                (order-ref-number uint64)
                (buy-sell uint8)
                (num-shares uint32)
                (symbol uint64)
                (price uint32)
                (match-number uint64))
               (81 cross-trade ; Q
                (locate uint16)
                (tracking uint16)
                (timestamp uint48)
                (num-shares-msb uint32)
                (num-shares uint32)
                (price uint32)
                (match-number uint64)
                (cross-type uint8))))))

 ;; Computes the global message seqnum for each message
    (def-counter seqnum32 32 :increment msg-type-sync :enable ethernet-input-tvalid :clear (delay seqnum-sync 3) :reset-value seqnum)

;; Only accepts the packets which don't have the correct IP addresse and port
    (setf (var bit packet-ok) (bit.and (= ip-dest-addr nasdaq-ip-addr) (= udp-dest-port nasdaq-udp-port)))

;; Stores various event codes into num-shares to reduce the AXI stream width
    (setf num-shares (case-expr msg-type
                                (83 event-code)
                                (72 trading-state)
                                (89 reg-sho-action)
                                (:default num-shares)))

;; Bundles the output into the command_out AXI4 stream data
    (setf command-out-tdata (concat msg-type
                                    order-ref-number
                                    prev-order-ref-number
                                    locate
                                    (= buy-sell #.(char-code #\B))
                                    price
                                    num-shares
                                    seqnum32
                                    timestamp))

    (setf command-out-tvalid (bit.and packet-ok
                                      (bit.or price-sync event-code-sync trading-state-sync reg-sho-action-sync
                                              (bit.and (bit.or (= msg-type 69) (= msg-type 88)) num-shares-sync))))))

;;; generates the Verilog file
(compile-to-verilog *nasdaq-itch-5.0-parser*
                    :verilog-file (merge-pathnames "nasdaq-itch-parser.v" *load-pathname*))
