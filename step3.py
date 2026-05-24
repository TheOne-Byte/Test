# ============================================================
# 42027 Software Defined Networks
# Ryu App - Step 3
#
# Features in this step:
#   ✓ Table-miss rule
#   ✓ ARP flooding on all switches
#   ✓ L2 forwarding for SW1–SW4
#
# What this gives you:
#   ✓ Working ping
#   ✓ Working iperf
#   ✓ Full baseline connectivity
#
# Not included yet:
#   ✗ SW5 policy rules (Step 4)
#   ✗ Monitoring thread (Step 5)
# ============================================================

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3


# MAC addresses (from assignment)
H1_MAC     = '00:00:00:00:00:01'
H2_MAC     = '00:00:00:00:00:02'
MGMT_MAC   = '00:00:00:00:00:03'
SERVER_MAC = '00:00:00:00:00:04'


class EnterpriseSDN(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # --------------------------------------------------------
    # Helper: install a flow rule
    # --------------------------------------------------------
    def add_flow(self, dp, priority, match, actions):
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(
            datapath=dp,
            priority=priority,
            match=match,
            instructions=inst
        )
        dp.send_msg(mod)

    # --------------------------------------------------------
    # Switch connects → install ARP + table-miss + L2 rules
    # --------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        dpid = dp.id

        self.logger.info(f"Switch connected: SW{dpid}")

        # -----------------------------
        # Table-miss rule
        # -----------------------------
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                          ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)

        # -----------------------------
        # ARP flood rule
        # -----------------------------
        match = parser.OFPMatch(eth_type=0x0806)  # ARP
        actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
        self.add_flow(dp, 1, match, actions)

        # ----------------------------------------------------
        # L2 FORWARDING RULES (SW1–SW4)
        # ----------------------------------------------------

        # -----------------------------
        # SW1
        # Ports:
        #   1 = h1
        #   2 = sw3
        #   3 = sw4
        # -----------------------------
        if dpid == 1:
            # h1 → others (server, h2, mgmt) → send to sw3 (port 2)
            for mac in [SERVER_MAC, H2_MAC, MGMT_MAC]:
                match = parser.OFPMatch(in_port=1, eth_dst=mac)
                actions = [parser.OFPActionOutput(2)]
                self.add_flow(dp, 5, match, actions)

            # return traffic → h1
            match = parser.OFPMatch(eth_dst=H1_MAC)
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(dp, 5, match, actions)

        # -----------------------------
        # SW2
        # Ports:
        #   1 = h2
        #   2 = sw3
        #   3 = sw4
        # -----------------------------
        elif dpid == 2:
            for mac in [SERVER_MAC, H1_MAC, MGMT_MAC]:
                match = parser.OFPMatch(in_port=1, eth_dst=mac)
                actions = [parser.OFPActionOutput(2)]
                self.add_flow(dp, 5, match, actions)

            match = parser.OFPMatch(eth_dst=H2_MAC)
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(dp, 5, match, actions)

        # -----------------------------
        # SW3
        # Ports:
        #   1 = sw1
        #   2 = sw2
        #   3 = sw5
        # -----------------------------
        elif dpid == 3:
            # toward server/mgmt → sw5 (port 3)
            for mac in [SERVER_MAC, MGMT_MAC]:
                match = parser.OFPMatch(eth_dst=mac)
                actions = [parser.OFPActionOutput(3)]
                self.add_flow(dp, 5, match, actions)

            # toward h1 → sw1 (port 1)
            match = parser.OFPMatch(eth_dst=H1_MAC)
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(dp, 5, match, actions)

            # toward h2 → sw2 (port 2)
            match = parser.OFPMatch(eth_dst=H2_MAC)
            actions = [parser.OFPActionOutput(2)]
            self.add_flow(dp, 5, match, actions)

        # -----------------------------
        # SW4
        # Ports:
        #   1 = sw1
        #   2 = sw2
        #   3 = sw5
        # -----------------------------
        elif dpid == 4:
            for mac in [SERVER_MAC, MGMT_MAC]:
                match = parser.OFPMatch(eth_dst=mac)
                actions = [parser.OFPActionOutput(3)]
                self.add_flow(dp, 5, match, actions)

            match = parser.OFPMatch(eth_dst=H1_MAC)
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(dp, 5, match, actions)

            match = parser.OFPMatch(eth_dst=H2_MAC)
            actions = [parser.OFPActionOutput(2)]
            self.add_flow(dp, 5, match, actions)

    # --------------------------------------------------------
    # Packet-in handler (ARP + unknown packets)
    # --------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        parser = dp.ofproto_parser
        ofp = dp.ofproto

        in_port = msg.match['in_port']

        # Flood unknown packets (ARP, initial traffic)
        actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]

        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )
        dp.send_msg(out)
