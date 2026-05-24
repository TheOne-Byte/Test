#!/usr/bin/env python3

from mininet.topo import Topo 
from mininet.net import Mininet 
from mininet.node import RemoteController, OVSKernelSwitch 
from mininet.link import TCLink 
from mininet.cli import CLI 
from mininet.log import setLogLevel 

class EnterpriseTopo(Topo): 
    def build(self): 
        # Create Infrastructure Switch Mesh Nodes
        sw1 = self.addSwitch('sw1') 
        sw2 = self.addSwitch('sw2') 
        sw3 = self.addSwitch('sw3') 
        sw4 = self.addSwitch('sw4') 
        sw5 = self.addSwitch('sw5') 

        # Provision Network Endpoint Terminals
        h1     = self.addHost('h1',     ip='10.0.0.1/24',   mac='00:00:00:00:00:01')
        h2     = self.addHost('h2',     ip='10.0.0.2/24',   mac='00:00:00:00:00:02')
        mgmt   = self.addHost('mgmt',   ip='10.0.0.254/24', mac='00:00:00:00:00:03')
        server = self.addHost('server', ip='10.0.0.11/24',  mac='00:00:00:00:00:04')

        # Map Structural Local Loop Link Profiles
        self.addLink(h1,     sw1, bw=10)
        self.addLink(h2,     sw2, bw=10)
        self.addLink(mgmt,   sw5, bw=10)
        self.addLink(server, sw5, bw=10)

        # Map Distribution Infrastructure Matrix Routing Interconnects
        self.addLink(sw1, sw3, bw=10) 
        self.addLink(sw1, sw4, bw=10) 
        self.addLink(sw2, sw3, bw=10) 
        self.addLink(sw2, sw4, bw=10) 
        self.addLink(sw3, sw5, bw=10) 
        self.addLink(sw4, sw5, bw=10) 

if __name__ == '__main__':
    setLogLevel('info')
    topo = EnterpriseTopo()
    
    # Initialize Core Simulation Engine with a strict Remote Controller profile mapping
    net = Mininet(topo=topo,
                  link=TCLink,
                  switch=OVSKernelSwitch,
                  controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6633))
    
    net.start()
    
    # Run absolute hardware shell overrides to snap switches out of standalone deadlocks
    import os
    for i in range(1, 6):
        print(f"*** Optimizing handshake configurations for sw{i}...")
        os.system(f'ovs-vsctl set-controller sw{i} tcp:127.0.0.1:6633')
        os.system(f'ovs-vsctl set bridge sw{i} protocols=OpenFlow13')
        os.system(f'ovs-vsctl set bridge sw{i} fail-mode=secure') # Never leak packets on timeout
        os.system(f'ovs-vsctl set bridge sw{i} stp_enable=true')  # Activate Spanning Tree loop mitigation

    print("\n*** Infrastructure setup complete. Switches actively establishing handshakes...\n")
    CLI(net)
    net.stop()
