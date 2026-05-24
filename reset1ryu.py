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

# dpid of sw5 (must match Mininet)
SW5_DPID = 5


class EnterpriseSDN(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(EnterpriseSDN, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

        # CSV file for stats
        self.csv_file = open('sw5_stats.csv', 'w', newline='')
        self.csv_writer = csv.writer(self.csv_file)
        self.csv_writer.writerow(['timestamp', 'dpid', 'match', 'byte_count', 'packet_count'])

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info('Register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == ofproto_v1_3.OFPPR_DELETE:
            if datapath.id in self.datapaths:
                self.logger.info('Unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Install proactive rules when switch connects."""
        datapath = ev.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.logger.info("Configuring switch %d", datapath.id)

        # 1. Default drop rule (lowest priority)
        match = parser.OFPMatch()
        self.add_flow(datapath, priority=0, match=match, actions=[])

        # 2. Allow TCP/UDP between H1/H2/Mgmt and Server
        # We don't do per-switch output ports here (for simplicity),
        # we just allow traffic based on IP and protocol and rely on normal L2 learning
        # if you extend this app. For now, we just "permit" by not dropping.

        # TCP flows
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
                eth_type=0x0800,
                ip_proto=6,
                ipv4_src=src,
                ipv4_dst=dst
            )
            actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
            self.add_flow(datapath, priority=100, match=match_tcp, actions=actions)

            # UDP
            match_udp = parser.OFPMatch(
                eth_type=0x0800,
                ip_proto=17,
                ipv4_src=src,
                ipv4_dst=dst
            )
            self.add_flow(datapath, priority=100, match=match_udp, actions=actions)

        # Optionally, allow ARP so hosts can resolve addresses
        match_arp = parser.OFPMatch(eth_type=0x0806)
        actions_arp = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        self.add_flow(datapath, priority=50, match=match_arp, actions=actions_arp)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    priority=priority, match=match,
                                    instructions=inst)
        datapath.send_msg(mod)

    def _monitor(self):
        """Periodically poll sw5 for flow stats."""
        while True:
            for dpid, dp in list(self.datapaths.items()):
                if dpid == SW5_DPID:
                    self._request_stats(dp)
            hub.sleep(10)  # every 10 seconds

    def _request_stats(self, datapath):
        self.logger.info('Sending stats request to sw5')
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id

        timestamp = time.time()

        for stat in body:
            # Only log IP flows (TCP/UDP)
            if stat.match.get('eth_type') == 0x0800 and stat.match.get('ip_proto') in [6, 17]:
                match_str = str(stat.match)
                byte_count = stat.byte_count
                packet_count = stat.packet_count

                self.logger.info('sw%d flow: %s bytes=%d pkts=%d',
                                 dpid, match_str, byte_count, packet_count)

                self.csv_writer.writerow([timestamp, dpid, match_str, byte_count, packet_count])
                self.csv_file.flush()

    def close(self):
        self.csv_file.close()
        super(EnterpriseSDN, self).close()
