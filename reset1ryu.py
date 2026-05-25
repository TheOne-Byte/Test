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

        # 1. Provide an absolute fallback for ARP discovery
        self.add_flow(dp, 100, parser.OFPMatch(eth_type=0x0806), [parser.OFPActionOutput(ofp.OFPP_FLOOD)])

        # 2. Part B1 Perimeter Lockdown (PROACTIVE DESIGN DESIGNATION)
        # Permitting traffic patterns targeting or originating from the core enterprise server
        # Explicit Layer-4 matches included to ensure fine-grained telemetry tracking
        
        # Proactive Rules for ICMP (Proto 1), TCP (Proto 6), and UDP (Proto 17) to/from Server
        for proto in [1, 6, 17]:
            # Traffic heading To Server -> High priority forwarding
            self.add_flow(dp, 10, parser.OFPMatch(eth_type=0x0800, ip_proto=proto, ipv4_dst=SERVER_IP), [parser.OFPActionOutput(ofp.OFPP_FLOOD)])
            # Traffic coming From Server -> High priority forwarding
            self.add_flow(dp, 10, parser.OFPMatch(eth_type=0x0800, ip_proto=proto, ipv4_src=SERVER_IP), [parser.OFPActionOutput(ofp.OFPP_FLOOD)])

        # Proactive Drop Rule: Any other IP traffic that bypasses the Server validation rules is dropped completely
        self.add_flow(dp, 5, parser.OFPMatch(eth_type=0x0800), [])

        # 3. Add dynamic Packet-In handler rule as an administrative fallback
        self.add_flow(dp, 0, parser.OFPMatch(), [parser.OFPActionOutput(ofp.OFPP_CONTROLLER)])

        # 4. Provision the sub-task B4 rate limiter band on the core switch
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

        _ipv4 = pkt.get_protocol(ipv4.ipv4)

        # Reactive L2 rule processing fallback for non-IP frame routing
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            actions = [parser.OFPActionOutput(out_port)]
            
            # Apply traffic engineering limits specifically to UDP streams crossing sw5
            if dpid == SW5_DPID and _ipv4 and _ipv4.proto == 17:
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=_ipv4.src, ipv4_dst=_ipv4.dst, ip_proto=17)
                self.add_flow(dp, 12, match, actions, meter_id=1) # Elevated priority to override base rules
            else:
                match = parser.OFPMatch(eth_dst=dst)
                self.add_flow(dp, 10, match, actions)

            out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
            dp.send_msg(out)
        else:
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
                match_fields = dict(stat.match.items())
                
                # Format a highly detailed, clean description tracking L3 & L4 metrics
                match_desc = []
                if 'ip_proto' in match_fields:
                    proto_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
                    p_num = match_fields['ip_proto']
                    match_desc.append(f"protocol:{proto_map.get(p_num, p_num)}")
                if 'eth_src' in match_fields: match_desc.append(f"src_mac:{match_fields['eth_src']}")
                if 'eth_dst' in match_fields: match_desc.append(f"dst_mac:{match_fields['eth_dst']}")
                if 'ipv4_src' in match_fields: match_desc.append(f"src_ip:{match_fields['ipv4_src']}")
                if 'ipv4_dst' in match_fields: match_desc.append(f"dst_ip:{match_fields['ipv4_dst']}")
                
                if not match_desc: 
                    match_desc = [f"Priority:{stat.priority}_Default_Rule"]
                
                label = " | ".join(match_desc)
                writer.writerow([time.strftime('%Y-%m-%d %H:%M:%S'), label, stat.byte_count, stat.packet_count])
