from mininet.topo import Topo 
from mininet.net import Mininet 
from mininet.node import RemoteController, OVSBridge # Changed to include OVSBridge
from mininet.link import TCLink 
from mininet.cli import CLI 
from mininet.log import setLogLevel 

class EnterpriseTopo(Topo): 
    def build(self): 
        # Enable Spanning Tree Protocol (STP) to stop broadcast loops
        sw1 = self.addSwitch('sw1', cls=OVSBridge, stp=True) 
        sw2 = self.addSwitch('sw2', cls=OVSBridge, stp=True) 
        sw3 = self.addSwitch('sw3', cls=OVSBridge, stp=True) 
        sw4 = self.addSwitch('sw4', cls=OVSBridge, stp=True) 
        sw5 = self.addSwitch('sw5', cls=OVSBridge, stp=True) 

        h1     = self.addHost('h1',     ip='10.0.0.1/24',   mac='00:00:00:00:00:01') 
        h2     = self.addHost('h2',     ip='10.0.0.2/24',   mac='00:00:00:00:00:02') 
        mgmt   = self.addHost('mgmt',   ip='10.0.0.254/24', mac='00:00:00:00:00:03') 
        server = self.addHost('server', ip='10.0.0.11/24',  mac='00:00:00:00:00:04') 

        self.addLink(h1,     sw1, bw=10) 
        self.addLink(h2,     sw2, bw=10) 
        self.addLink(mgmt,   sw5, bw=10) 
        self.addLink(server, sw5, bw=1000) 

        self.addLink(sw1, sw3, bw=100,  delay='2ms') 
        self.addLink(sw1, sw4, bw=100,  delay='2ms') 
        self.addLink(sw2, sw3, bw=100,  delay='2ms') 
        self.addLink(sw2, sw4, bw=100,  delay='2ms') 
        self.addLink(sw3, sw5, bw=1000, delay='2ms') 
        self.addLink(sw4, sw5, bw=1000, delay='2ms') 

topos = {'enterprisetopo': EnterpriseTopo} 

if __name__ == '__main__': 
    setLogLevel('info') 
    topo = EnterpriseTopo() 
    net = Mininet(topo=topo, controller=RemoteController, link=TCLink) 
    net.start() 
    CLI(net) 
    net.stop()
