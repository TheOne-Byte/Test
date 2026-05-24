from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel

class EnterpriseTopo(Topo):
    def build(self):

        # Hosts
        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
        mgmt = self.addHost('mgmt', ip='10.0.0.254/24', mac='00:00:00:00:00:03')
        server = self.addHost('server', ip='10.0.0.11/24', mac='00:00:00:00:00:04')

        # Switches (dpids chosen to match names: sw1 -> 1, sw2 -> 2, etc.)
        sw1 = self.addSwitch('sw1', dpid='0000000000000001')
        sw2 = self.addSwitch('sw2', dpid='0000000000000002')
        sw3 = self.addSwitch('sw3', dpid='0000000000000003')
        sw4 = self.addSwitch('sw4', dpid='0000000000000004')
        sw5 = self.addSwitch('sw5', dpid='0000000000000005')

        # Host–switch links
        # 10 Mbps links to h1, h2, mgmt; 1 Gbps to server
        self.addLink(h1, sw1, cls=TCLink, bw=10, delay='2ms')
        self.addLink(h2, sw2, cls=TCLink, bw=10, delay='2ms')
        self.addLink(mgmt, sw5, cls=TCLink, bw=10, delay='2ms')
        self.addLink(server, sw5, cls=TCLink, bw=1000, delay='2ms')

        # Inter-switch links (all with 2 ms delay)
        # From diagram: sw1–sw3 100 Mbps, sw2–sw3 100 Mbps,
        # sw1–sw4 100 Mbps, sw2–sw4 100 Mbps,
        # sw3–sw5 1 Gbps, sw4–sw5 1 Gbps
        self.addLink(sw1, sw3, cls=TCLink, bw=100, delay='2ms')
        self.addLink(sw2, sw3, cls=TCLink, bw=100, delay='2ms')
        self.addLink(sw1, sw4, cls=TCLink, bw=100, delay='2ms')
        self.addLink(sw2, sw4, cls=TCLink, bw=100, delay='2ms')
        self.addLink(sw3, sw5, cls=TCLink, bw=1000, delay='2ms')
        self.addLink(sw4, sw5, cls=TCLink, bw=1000, delay='2ms')


def run():
    topo = EnterpriseTopo()
    net = Mininet(
        topo=topo,
        controller=None,              # we’ll use external Ryu controller
        switch=OVSKernelSwitch,
        link=TCLink,
        autoSetMacs=False,
        autoStaticArp=False
    )

    # Attach remote controller (Ryu default: 127.0.0.1:6633 or 6653 depending on your config)
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)

    net.start()

    print("*** Network topology:")
    net.pingAll()

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
