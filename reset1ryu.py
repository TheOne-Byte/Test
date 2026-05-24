from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
import csv
import time

SERVER_IP = '10.0.0.11'
H1_IP = '10.0.0.1'
H2_IP = '10.0.0.2'
MGMT_IP = '10.0.0.254'

SW5_DPID = 5


class EnterpriseSDN(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(EnterpriseSDN, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

        self.csv_file = open('sw5_stats.csv', 'w', newline='')
        self.csv_writer = csv.writer(self.csv_file)
        self.csv_writer.writerow(['timestamp', 'dpid', 'match', 'byte_count', 'packet_count'])

    # Register datapaths
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def _state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
            self.logger.info("Register datapath: %016x", dp.id)
        elif ev.state == ofproto_v1_3.OFPPR_DELETE:
            if dp.id in self.datapaths:
                del self.datapaths[dp.id]

    # FIXED HANDLER
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath   # ✅ FIXED
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.logger.info("Configuring switch %d", datapath.id)

        # Default DROP rule
        match = parser.OFPMatch()
        self.add_flow(datapath, 0, match, [])

        # Allow ARP
        match_arp = parser.OFPMatch(eth_type=0x0806)
        self.add_flow(datapath, 50, match_arp,
                      [parser.OFPActionOutput(ofproto.OFPP_NORMAL)])

        allowed_pairs = [
            (H1_IP, SERVER_IP),
            (SERVER_IP, H1_IP),
            (H2_IP, SERVER_IP),
            (SERVER_IP, H2_IP),
            (MGMT_IP, SERVER_IP),
            (SERVER_IP, MGMT_IP),
        ]

        for src, dst in allowed_pairs:
            # TCP
            match_tcp = parser.OFPMatch(
                eth_type=0x0800, ip_proto=6,
                ipv4_src=src, ipv4_dst=dst
            )
            self.add_flow(datapath, 100, match_tcp,
                          [parser.OFPActionOutput(ofproto.OFPP_NORMAL)])

            # UDP
            match_udp = parser.OFPMatch(
                eth_type=0x0800, ip_proto=17,
                ipv4_src=src, ipv4_dst=dst
            )
            self.add_flow(datapath, 100, match_udp,
                          [parser.OFPActionOutput(ofproto.OFPP_NORMAL)])

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    # Monitoring thread
    def _monitor(self):
        while True:
            for dpid, dp in self.datapaths.items():
                if dpid == SW5_DPID:
                    self._request_stats(dp)
            hub.sleep(10)

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        timestamp = time.time()

        for stat in ev.msg.body:
            if stat.match.get('eth_type') == 0x0800 and stat.match.get('ip_proto')
