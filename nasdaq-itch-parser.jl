hw_module(nasdaq_itch_parser, "Extraction and parsing of Nasdaq ITCH 5.0 orders and trade related messages",
          stream_in = ethernet_input, stream_out = command_out, frequency = 322.265625e6);

# The general interface
@input::uint32 fpga-time::("The FPGA time counter")

# The Ethernet AXI input stream interface
@input::uint32 ethernet_input_tdata;
@input::uint4 ethernet_input_tkeep;
@input::bit ethernet_input_tlast ethernet_input_tvalid;
@output::bit ethernet_input_tready::special_use;

# The commands AXI output stream interface
@input command_out_tready::bit;
@output command_out_tdata::uint297;
@output command_out_tvalid::bit;

# Let's register the inputs
ethernet_input_tlast = register(ethernet_input_tlast);

# Adding an extra clock cycle after the last word of each packet
change_execution((after_packet, :exec_when, ethernet_input_tlast));

start_of_packet::bit = falling_edge(after_packet, initial_value = 1);

# The memory mapped registers interface
def_mmap_interface(config_registers, "The config/status registers", data_width = 32, nb_words = 8);

@with_var_options (interface = config_registers) begin
    @input::uint32 nasdaq_ip_addr::(:untimed, "The IP address of the incoming NASDAQ feed.", :initial_value = 0xE9360C65);
    @input::uint16 nasdaq_udp_port::(:untimed, "The IP port of the incoming NASDAQ feed.", :initial_value = 26400);
end;

# The message parser takes the description of the messages and generates the hardware needed to decode them
def_message_parser2(parser, sop = start_of_packet, data_valid = ~after_packet & ethernet_input_tvalid
                    ,tkeep = ethernet_input_tkeep, data_in = ethernet_input_tdata,
                    protocol_desc =
                    (
                  # Ethernet header
                     dst_mac::uint48,
                     src_mac::uint48,
                     eth_type::uint16,
                  # IP header
                     version_and_IHL::uint8,
                     DSCP_ECN::uint8,
                     total_length::uint16,
                     identification::uint16,
                     flag_-and_fragment_offset::uint16,
                     time_to_live::uint8,
                     protocol::uint8,
                     header_checksum::uint16,
                     ip_src_addr::uint32,
                     ip_dest_addr::uint32,
                  # UDP header
                     udp_src_port::uint16,
                     udp_dest_port::uint16,
                     udp_len::uint16,
                     udp_checksum::uint16,
                  # MOLD header
                     mold_session::uint64,
                     mold_session_msb::uint16,
                     seqnum::uint64,
                     msg_count::uint16,
                  # ITCH 5.0 Messages
                     (:loop, (msg_length::uint16, :nil),
                      msg_type::uint8,
                      (:case, (msg_type),
                       (83, system_event_message, # S
                        locate::uint16,
                        tracking::uint16,
                        timestamp::uint48,
                        event_code::uint8),
                       (72, stock_trading_action, # H
                        locate::uint16,
                        tracking::uint16,
                        timestamp::uint48,
                        symbol::uint64,
                        trading_state::uint8),
                       (89, reg_sho,  # Y
                        locate::uint16,
                        tracking::uint16,
                        timestamp::uint48,
                        symbol::uint64,
                        reg_sho_action::uint8),
                       (65, add_order, # A
                        locate::uint16,
                        tracking::uint16,
                        timestamp::uint48,
                        order_ref_number::uint64,
                        buy_sell::uint8,
                        num_shares::uint32,
                        symbol::uint64,
                        price::uint32),
                       (70, add_order_with_mpid, # F
                        locate::uint16,
                        tracking::uint16,
                        timestamp::uint48,
                        order_ref_number::uint64,
                        buy_sell::uint8,
                        num_shares::uint32,
                        symbol::uint64,
                        price::uint32,
                        attribution::uint32),
                       (85, order_replace, # U
                        locate::uint16,
                        tracking::uint16,
                        timestamp::uint48,
                        prev_order_ref_number::uint64,
                        order_ref_number::uint64,
                        num_shares::uint32,
                        price::uint32),
                       (69, order_executed,  # E
                        locate::uint16,
                        tracking::uint16,
                        timestamp::uint48,
                        order_ref_number::uint64,
                        num_shares::uint32,
                        match_number::uint64),
                       (67, order_executed_with_price, # C
                        locate::uint16,
                        tracking::uint16,
                        timestamp::uint48,
                        order_ref_number::uint64,
                        num_shares::uint32,
                        match_number::uint64,
                        printable::uint8,
                        price::uint32),
                       (88, order_cancel, # X
                        locate::uint16,
                        tracking::uint16,
                        timestamp::uint48,
                        order_ref_number::uint64,
                        num_shares::uint32),
                       (68, order_delete, # D
                        locate::uint16,
                        tracking::uint16,
                        timestamp::uint48,
                        order_ref_number::uint64),
                       (80, trade, # P
                        locate::uint16,
                        tracking::uint16,
                        timestamp::uint48,
                        order_ref_number::uint64,
                        buy_sell::uint8,
                        num_shares::uint32,
                        symbol::uint64,
                        price::uint32,
                        match_number::uint64),
                       (81, cross_trade, # Q
                        locate::uint16,
                        tracking::uint16,
                        timestamp::uint48,
                        num_shares_msb::uint32,
                        num_shares::uint32,
                        price::uint32,
                        match_number::uint64,
                        cross_type::uint8)))));

 # Computes the global message seqnum for each message
def_counter(seqnum32::32, increment = msg_type_sync, enable = ethernet_input_tvalid, clear = delay(seqnum_sync, 3), reset_value = seqnum);

# Only accepts the packets which don't have the correct IP addresse and port
packet_ok::bit = (ip_dest_addr == nasdaq_ip_addr) & (udp_dest_port == nasdaq_udp_port);

# Stores various event codes into num_shares to reduce the AXI stream width
num_shares = case_expr(msg_type, ((83, event_code), (72, trading_state), (89, reg_sho_action), (:default, num_shares)))

# Bundles the output into the command_out AXI4 stream data
command_out_tdata = register(concat(msg_type, order_ref_number, prev_order_ref_number, locate,
                                    buy_sell == 66, price, num_shares, seqnum32,
                                    timestamp));

# Computes when the command out is valid
command_out_tvalid = packet_ok & (price_sync | event_code_sync | trading_state_sync | reg_sho_action_sync |
                                  ((msg_type == 69) | (msg_type == 88)) & num_shares_sync);
