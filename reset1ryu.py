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
        self.mac_to_port = {}
        self.monitor_thread = hub.spawn(self._monitor) 
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

        # 1. Provide an absolute fallback for ARP discovery
        self.add_flow(dp, 100, parser.OFPMatch(eth_type=0x0806), [parser.OFPActionOutput(ofp.OFPP_FLOOD)])

        # 2. Add dynamic Packet-In handler rule so switches can discover host ports natively
        self.add_flow(dp, 0, parser.OFPMatch(), [parser.OFPActionOutput(ofp.OFPP_CONTROLLER)])

        # 3. Provision the sub-task B4 rate limiter band on the core switch
        if dpid == SW5_DPID:
            self.sw5_dp = dp
            self.add_meter(dp, meter_id=1, rate_kbps=5000)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        in_port = msg.match['in_port']

        # Parse ethernet frames to locate MAC endpoints safely
        from ryu.lib.packet import packet, ethernet, ipv4
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        dst = eth.dst
        src = eth.src
        dpid = dp.id

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # Part B1 Perimeter Lockdown: If it's IP traffic, strictly enforce Server-Only routing
        _ipv4 = pkt.get_protocol(ipv4.ipv4)
        if _ipv4:
            src_ip = _ipv4.src
            dst_ip = _ipv4.dst
            
            # If traffic isn't heading to or coming from the Server, drop it immediately!
            if dst_ip != SERVER_IP and src_ip != SERVER_IP:
                self.add_flow(dp, 5, parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip), [])
                return

        # If we know where the destination MAC is, write a permanent flow rule
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            actions = [parser.OFPActionOutput(out_port)]
            
            # Apply traffic engineering limits to UDP streams crossing sw5
            if dpid == SW5_DPID and _ipv4 and _ipv4.proto == 17:
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=_ipv4.src, ipv4_dst=_ipv4.dst)
                self.add_flow(dp, 10, match, actions, meter_id=1)
            else:
                match = parser.OFPMatch(eth_dst=dst)
                self.add_flow(dp, 10, match, actions)

            # Send the current packet out
            out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
            dp.send_msg(out)
        else:
            # If we don't know where it is yet, flood it safely to discover it
            actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
            out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
            dp.send_msg(out)

    # --- B2/B3 Performance Monitoring Engine ---
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
                if 'ipv4_src' not in match: continue 
                writer.writerow([time.strftime('%Y-%m-%d %H:%M:%S'), f"src:{match['ipv4_src']}->dst:{match['ipv4_dst']}", stat.byte_count, stat.packet_count])
