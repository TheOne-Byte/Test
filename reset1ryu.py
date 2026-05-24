from ryu.base import app_manager 
from ryu.controller import ofp_event 
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls 
from ryu.ofproto import ofproto_v1_3 
from ryu.lib import hub 
import csv 
import time 

SW5_DPID = 5 

# Hardware Layer MAC Maps
H1_MAC     = '00:00:00:00:00:01' 
H2_MAC     = '00:00:00:00:00:02' 
MGMT_MAC   = '00:00:00:00:00:03' 
SERVER_MAC = '00:00:00:00:00:04' 

# Network Layer IP Maps
SERVER_IP = '10.0.0.11' 
H1_IP     = '10.0.0.1' 
H2_IP     = '10.0.0.2' 
MGMT_IP   = '10.0.0.254' 


class EnterpriseSDN(app_manager.RyuApp): 
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION] 

    def __init__(self, *args, **kwargs): 
        super(EnterpriseSDN, self).__init__(*args, **kwargs) 
        self.sw5_dp = None 
        self.monitor_thread = hub.spawn(self._monitor) 
        # Instantiating cleaner output capture document for B2 metrics
        with open('sw5_stats.csv', 'w', newline='') as f: 
            csv.writer(f).writerow(['timestamp', 'flow_match', 'byte_count', 'packet_count']) 

    def add_flow(self, dp, priority, match, actions, meter_id=None): 
        ofp = dp.ofproto 
        parser = dp.ofproto_parser 
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)] 
        if meter_id is not None:
            inst.append(parser.OFPInstructionMeter(meter_id, ofp.OFPIT_METER))
        mod = parser.OFPFlowMod(datapath=dp, priority=priority, match=match, instructions=inst) 
        dp.send_msg(mod) 

    def add_meter(self, dp, meter_id, rate_kbps):
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        bands = [parser.OFPMeterBandDrop(rate=rate_kbps, burst_size=0)]
        mod = parser.OFPMeterMod(datapath=dp, command=ofp.OFPMC_ADD, flags=ofp.OFPMF_KBPS, meter_id=meter_id, bands=bands)
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER) 
    def switch_features_handler(self, ev): 
        dp = ev.msg.datapath 
        ofp = dp.ofproto 
        parser = dp.ofproto_parser 
        dpid = dp.id 

        flood = [parser.OFPActionOutput(ofp.OFPP_FLOOD)] 

        # High-priority globally transparent fallback for infrastructure ARP tracking
        self.add_flow(dp, 100, parser.OFPMatch(eth_type=0x0806), flood)

        # --- SW1 Gateway Interface --- 
        if dpid == 1: 
            for proto in [6, 17, 1]: # Proactive layer 4 verification vectors
                self.add_flow(dp, 10, parser.OFPMatch(eth_type=0x0800, ip_proto=proto, ipv4_dst=SERVER_IP), [parser.OFPActionOutput(2)])
                self.add_flow(dp, 10, parser.OFPMatch(eth_type=0x0800, ip_proto=proto, ipv4_src=SERVER_IP, ipv4_dst=H1_IP), [parser.OFPActionOutput(1)])
            # Part B1 Perimeter Lock down
            self.add_flow(dp, 5, parser.OFPMatch(eth_type=0x0800), [])

        # --- SW2 Gateway Interface --- 
        elif dpid == 2: 
            for proto in [6, 17, 1]:
                self.add_flow(dp, 10, parser.OFPMatch(eth_type=0x0800, ip_proto=proto, ipv4_dst=SERVER_IP), [parser.OFPActionOutput(2)])
                self.add_flow(dp, 10, parser.OFPMatch(eth_type=0x0800, ip_proto=proto, ipv4_src=SERVER_IP, ipv4_dst=H2_IP), [parser.OFPActionOutput(1)])
            self.add_flow(dp, 5, parser.OFPMatch(eth_type=0x0800), [])

        # --- SW3 Core Matrix --- 
        elif dpid == 3: 
            for proto in [6, 17, 1]:
                self.add_flow(dp, 10, parser.OFPMatch(eth_type=0x0800, ip_proto=proto, ipv4_dst=SERVER_IP), [parser.OFPActionOutput(3)])
                self.add_flow(dp, 10, parser.OFPMatch(eth_type=0x0800, ip_proto=proto, ipv4_src=SERVER_IP, ipv4_dst=H1_IP), [parser.OFPActionOutput(1)])
                self.add_flow(dp, 10, parser.OFPMatch(eth_type=0x0800, ip_proto=proto, ipv4_src=SERVER_IP, ipv4_dst=H2_IP), [parser.OFPActionOutput(2)])
            self.add_flow(dp, 5, parser.OFPMatch(eth_type=0x0800), [])

        # --- SW4 Core Matrix --- 
        elif dpid == 4: 
            for proto in [6, 17, 1]:
                self.add_flow(dp, 10, parser.OFPMatch(eth_type=0x0800, ip_proto=proto, ipv4_dst=SERVER_IP), [parser.OFPActionOutput(3)])
                self.add_flow(dp, 10, parser.OFPMatch(eth_type=0x0800, ip_proto=proto, ipv4_src=SERVER_IP, ipv4_dst=H1_IP), [parser.OFPActionOutput(1)])
                self.add_flow(dp, 10, parser.OFPMatch(eth_type=0x0800, ip_proto=proto, ipv4_src=SERVER_IP, ipv4_dst=H2_IP), [parser.OFPActionOutput(2)])
            self.add_flow(dp, 5, parser.OFPMatch(eth_type=0x0800), [])

        # --- SW5 Core Data Center Aggregator --- 
        elif dpid == 5: 
            self.sw5_dp = dp 
            # Implement 5 Mbps hard limiting rate band for sub-task B4
            self.add_meter(dp, meter_id=1, rate_kbps=5000)

            host_routing_table = [(H1_IP, 3), (H2_IP, 3), (MGMT_IP, 1)]

            for host_ip, host_port in host_routing_table:
                for proto in [6, 17, 1]: 
                    if proto == 17:  # intercept UDP packets and push into the pipeline meter table
                        self.add_flow(dp, 10, parser.OFPMatch(eth_type=0x0800, ip_proto=proto, ipv4_src=host_ip, ipv4_dst=SERVER_IP), [parser.OFPActionOutput(2)], meter_id=1)
                        self.add_flow(dp, 10, parser.OFPMatch(eth_type=0x0800, ip_proto=proto, ipv4_src=SERVER_IP, ipv4_dst=host_ip), [parser.OFPActionOutput(host_port)], meter_id=1)
                    else:            # TCP and ICMP route natively through clean pipes
                        self.add_flow(dp, 10, parser.OFPMatch(eth_type=0x0800, ip_proto=proto, ipv4_src=host_ip, ipv4_dst=SERVER_IP), [parser.OFPActionOutput(2)])
                        self.add_flow(dp, 10, parser.OFPMatch(eth_type=0x0800, ip_proto=proto, ipv4_src=SERVER_IP, ipv4_dst=host_ip), [parser.OFPActionOutput(host_port)])

            # Isolation drop filter for non-server IP packets crossing core switch space
            self.add_flow(dp, 5, parser.OFPMatch(eth_type=0x0800), []) 

            # Hardcoded L2 destination overrides for switch fabric structural safety
            self.add_flow(dp, 3, parser.OFPMatch(eth_dst=SERVER_MAC), [parser.OFPActionOutput(2)]) 
            self.add_flow(dp, 3, parser.OFPMatch(eth_dst=MGMT_MAC),   [parser.OFPActionOutput(1)]) 
            self.add_flow(dp, 3, parser.OFPMatch(eth_dst=H1_MAC),     [parser.OFPActionOutput(3)]) 
            self.add_flow(dp, 3, parser.OFPMatch(eth_dst=H2_MAC),     [parser.OFPActionOutput(3)]) 

    # --- B2 Performance Polling Loops ---
    def _monitor(self): 
        while True: 
            if self.sw5_dp is not None: 
                self.sw5_dp.send_msg(self.sw5_dp.ofproto_parser.OFPFlowStatsRequest(self.sw5_dp)) 
            hub.sleep(10) 

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER) 
    def flow_stats_reply_handler(self, ev): 
        if ev.msg.datapath.id != SW5_DPID: return 
        with open('sw5_stats.csv', 'a', newline='') as f: 
            writer = csv.writer(f) 
            for stat in ev.msg.body: 
                match = stat.match 
                if 'ip_proto' not in match: continue 
                proto = match['ip_proto'] 
                if proto not in (6, 17): continue 
                label = 'TCP' if proto == 6 else 'UDP' 
                writer.writerow([time.strftime('%Y-%m-%d %H:%M:%S'), label, stat.byte_count, stat.packet_count])
