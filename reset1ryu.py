from ryu.base import app_manager 
from ryu.controller import ofp_event 
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls 
from ryu.ofproto import ofproto_v1_3 
from ryu.lib import hub 
import csv 
import time 

SW5_DPID = 5 

# Standardized Physical Ports from your network layout: 
# sw1: eth1=h1, eth2=sw3, eth3=sw4 
# sw2: eth1=h2, eth2=sw3, eth3=sw4 
# sw3: eth1=sw1, eth2=sw2, eth3=sw5 
# sw4: eth1=sw1, eth2=sw2, eth3=sw5 
# sw5: eth1=mgmt, eth2=server, eth3=sw3, eth4=sw4 

# Hardware MAC Addresses
H1_MAC     = '00:00:00:00:00:01' 
H2_MAC     = '00:00:00:00:00:02' 
MGMT_MAC   = '00:00:00:00:00:03' 
SERVER_MAC = '00:00:00:00:00:04' 

# Network Layer IP Mapping
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
        # Create/Truncate stats file with header rows for Sub-task B2
        with open('sw5_stats.csv', 'w', newline='') as f: 
            csv.writer(f).writerow(['timestamp', 'flow_match', 'byte_count', 'packet_count']) 

    def add_flow(self, dp, priority, match, actions, meter_id=None): 
        ofp = dp.ofproto 
        parser = dp.ofproto_parser 
        
        # Build standard output instruction pipeline
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)] 
        
        # Inject traffic-shaping meter instruction if defined for Part B4
        if meter_id is not None:
            inst.append(parser.OFPInstructionMeter(meter_id, ofp.OFPIT_METER))
            
        mod = parser.OFPFlowMod(datapath=dp, priority=priority, 
                                match=match, instructions=inst) 
        dp.send_msg(mod) 

    def add_meter(self, dp, meter_id, rate_kbps):
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        
        # Define a hard band that drops packets exceeding our threshold
        bands = [parser.OFPMeterBandDrop(rate=rate_kbps, burst_size=0)]
        
        mod = parser.OFPMeterMod(
            datapath=dp, 
            command=ofp.OFPMC_ADD,
            flags=ofp.OFPMF_KBPS, # Measuring limits in kbps
            meter_id=meter_id,
            bands=bands
        )
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER) 
    def switch_features_handler(self, ev): 
        dp = ev.msg.datapath 
        ofp = dp.ofproto 
        parser = dp.ofproto_parser 
        dpid = dp.id 

        if dpid == SW5_DPID: 
            self.sw5_dp = dp 

        # Broadcast fallback token for ARP initialization 
        flood = [parser.OFPActionOutput(ofp.OFPP_FLOOD)] 

        # ==========================================
        # --- SW1 (Edge Switch for H1) ---
        # ==========================================
        if dpid == 1: 
            self.add_flow(dp, 1, parser.OFPMatch(eth_type=0x0806), flood) # Permit ARP
            
            for proto in [6, 17, 1]: # Proactively map Layer 4 (6=TCP, 17=UDP, 1=ICMP)
                # Client-to-Server Uplink: Forward out via port 2 toward sw3
                self.add_flow(dp, 10, parser.OFPMatch(eth_type=0x0800, ip_proto=proto, ipv4_dst=SERVER_IP), [parser.OFPActionOutput(2)])
                # Server-to-Client Downlink: Forward directly out port 1 to h1
                self.add_flow(dp, 10, parser.OFPMatch(eth_type=0x0800, ip_proto=proto, ipv4_src=SERVER_IP, ipv4_dst=H1_IP), [parser.OFPActionOutput(1)])
            
            # Sub-task B1: Proactively drop isolated internal host-to-host streams
            self.add_flow(dp, 5, parser.OFPMatch(eth_type=0x0800), [])

        # ==========================================
        # --- SW2 (Edge Switch for H2) ---
        # ==========================================
        elif dpid == 2: 
            self.add_flow(dp, 1, parser.OFPMatch(eth_type=0x0806), flood) # Permit ARP
            
            for proto in [6, 17, 1]:
                # Client-to-Server Uplink: Forward out via port 2 toward sw3
                self.add_flow(dp, 10, parser.OFPMatch(eth_type=0x0800, ip_proto=proto, ipv4_dst=SERVER_IP), [parser.OFPActionOutput(2)])
                # Server-to-Client Downlink: Forward directly out port 1 to h2
                self.add_flow(dp, 10, parser.OFPMatch(eth_type=0x0800, ip_proto=proto, ipv4_src=SERVER_IP, ipv4_dst=H2_IP), [parser.OFPActionOutput(1)])
            
            # Sub-task B1: Proactively drop isolated internal host-to-host streams
            self.add_flow(dp, 5, parser.OFPMatch(eth_type=0x0800), [])

        # ==========================================
        # --- SW3 (Core Distribution Layer) ---
        # ==========================================
        elif dpid == 3: 
            self.add_flow(dp, 1, parser.OFPMatch(eth_type=0x0806), flood) 
            
            for proto in [6, 17, 1]:
                # Upbound Server traffic crosses Port 3 up to sw5
                self.add_flow(dp, 10, parser.OFPMatch(eth_type=0x0800, ip_proto=proto, ipv4_dst=SERVER_IP), [parser.OFPActionOutput(3)])
                # Return flows forwarded down to respective edge switches
                self.add_flow(dp, 10, parser.OFPMatch(eth_type=0x0800, ip_proto=proto, ipv4_src=SERVER_IP, ipv4_dst=H1_IP), [parser.OFPActionOutput(1)])
                self.add_flow(dp, 10, parser.OFPMatch(eth_type=0x0800, ip_proto=proto, ipv4_src=SERVER_IP, ipv4_dst=H2_IP), [parser.OFPActionOutput(2)])
            
            # Block direct lateral host shortcut paths
            self.add_flow(dp, 5, parser.OFPMatch(eth_type=0x0800), [])

        # ==========================================
        # --- SW4 (Redundant Path Link) ---
        # ==========================================
        elif dpid == 4: 
            self.add_flow(dp, 1, parser.OFPMatch(eth_type=0x0806), flood) 
            
            for proto in [6, 17, 1]:
                self.add_flow(dp, 10, parser.OFPMatch(eth_type=0x0800, ip_proto=proto, ipv4_dst=SERVER_IP), [parser.OFPActionOutput(3)])
                self.add_flow(dp, 10, parser.OFPMatch(eth_type=0x0800, ip_proto=proto, ipv4_src=SERVER_IP, ipv4_dst=H1_IP), [parser.OFPActionOutput(1)])
                self.add_flow(dp, 10, parser.OFPMatch(eth_type=0x0800, ip_proto=proto, ipv4_src=SERVER_IP, ipv4_dst=H2_IP), [parser.OFPActionOutput(2)])
            
            self.add_flow(dp, 5, parser.OFPMatch(eth_type=0x0800), [])

        # ==========================================
        # --- SW5 (Core Server Switch) ---
        # ==========================================
        elif dpid == 5: 
            self.sw5_dp = dp 
            self.add_flow(dp, 1, parser.OFPMatch(eth_type=0x0806), flood) 

            # Sub-task B4 Implementation: Provision a 5 Mbps (5000 kbps) Traffic Engineering Meter
            self.add_meter(dp, meter_id=1, rate_kbps=5000)

            # Interface map for incoming and outgoing client connections
            host_routing_table = [
                (H1_IP, 3),   # Reached via distribution switch link (port 3)
                (H2_IP, 3),   # Reached via distribution switch link (port 3)
                (MGMT_IP, 1)  # Directly wired on Local Port 1
            ]

            for host_ip, host_port in host_routing_table:
                for proto in [6, 17, 1]: 
                    
                    # Traffic directed TO the Server (Port 2)
                    if proto == 17:  # Rate limit UDP by binding to Meter ID 1
                        self.add_flow(dp, 10, 
                                      parser.OFPMatch(eth_type=0x0800, ip_proto=proto, ipv4_src=host_ip, ipv4_dst=SERVER_IP), 
                                      [parser.OFPActionOutput(2)], meter_id=1)
                    else:            # TCP and ICMP flows pass unmetered
                        self.add_flow(dp, 10, 
                                      parser.OFPMatch(eth_type=0x0800, ip_proto=proto, ipv4_src=host_ip, ipv4_dst=SERVER_IP), 
                                      [parser.OFPActionOutput(2)])
                    
                    # Traffic traveling FROM the Server back out to hosts
                    if proto == 17:  # Rate limit downstream UDP traffic too
                        self.add_flow(dp, 10, 
                                      parser.OFPMatch(eth_type=0x0800, ip_proto=proto, ipv4_src=SERVER_IP, ipv4_dst=host_ip), 
                                      [parser.OFPActionOutput(host_port)], meter_id=1)
                    else:
                        self.add_flow(dp, 10, 
                                      parser.OFPMatch(eth_type=0x0800, ip_proto=proto, ipv4_src=SERVER_IP, ipv4_dst=host_ip), 
                                      [parser.OFPActionOutput(host_port)])

            # Strict Drop for all host-to-host traffic not involving the server
            self.add_flow(dp, 5, parser.OFPMatch(eth_type=0x0800), []) 

            # Hardcoded Layer 2 Fallbacks for infrastructure safety
            self.add_flow(dp, 3, parser.OFPMatch(eth_dst=SERVER_MAC), [parser.OFPActionOutput(2)]) 
            self.add_flow(dp, 3, parser.OFPMatch(eth_dst=MGMT_MAC),   [parser.OFPActionOutput(1)]) 
            self.add_flow(dp, 3, parser.OFPMatch(eth_dst=H1_MAC),     [parser.OFPActionOutput(3)]) 
            self.add_flow(dp, 3, parser.OFPMatch(eth_dst=H2_MAC),     [parser.OFPActionOutput(3)]) 

    # ==========================================
    # --- B2 Traffic Polling Engine ---
    # ==========================================
    def _monitor(self): 
        while True: 
            if self.sw5_dp is not None: 
                self.sw5_dp.send_msg( 
                    self.sw5_dp.ofproto_parser.OFPFlowStatsRequest(self.sw5_dp)) 
            hub.sleep(10) 

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER) 
    def flow_stats_reply_handler(self, ev): 
        if ev.msg.datapath.id != SW5_DPID: 
            return 
        with open('sw5_stats.csv', 'a', newline='') as f: 
            writer = csv.writer(f) 
            for stat in ev.msg.body: 
                match = stat.match 
                if 'ip_proto' not in match: 
                    continue 
                proto = match['ip_proto'] 
                if proto not in (6, 17): 
                    continue 
                label = 'TCP' if proto == 6 else 'UDP' 
                writer.writerow([time.strftime('%Y-%m-%d %H:%M:%S'), 
                                 label, stat.byte_count, stat.packet_count]) 
                self.logger.info('sw5 %s bytes=%d packets=%d', 
                                 label, stat.byte_count, stat.packet_count)
