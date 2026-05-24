from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel

class EnterpriseTopo(Topo):
    def build(self):

        # Hosts
        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')
        mgmt = self.addHost('mgmt', ip='10.0.0.254/24')
        server = self.addHost('server', ip='10.0.0.11/24')

        # Switches
        sw1 = self.addSwitch('sw1')
        sw2 = self.addSwitch('sw2')
        sw3 = self.addSwitch('sw3')
        sw4 = self.addSwitch('sw4')
        sw5 = self.addSwitch('sw5')

        # Host links
        self.addLink(h1, sw1, cls=TCLink, bw=10, delay='2ms')
        self.addLink(h2, sw2, cls=TCLink, bw=10, delay='2ms')
        self.addLink(mgmt, sw5, cls=TCLink, bw=10, delay='2ms')
        self.addLink(server, sw5, cls=TCLink, bw=1000, delay='2ms')

        # Inter-switch links
        self.addLink(sw1, sw3, cls=TCLink, bw=100, delay='2ms')
        self.addLink(sw2, sw3, cls=TCLink, bw=100, delay='2ms')
        self.addLink(sw1, sw4, cls=TCLink, bw=100, delay='2ms')
        self.addLink(sw2, sw4, cls=TCLink, bw=100, delay='2ms')
        self.addLink(sw3, sw5, cls=TCLink, bw=1000, delay='2ms')
        self.addLink(sw4, sw5, cls=TCLink, bw=1000, delay='2ms')

def run():
    topo = EnterpriseTopo()

    # Faucet is the controller, so controller=None
    net = Mininet(
        topo=topo,
        controller=None,
        switch=OVSKernelSwitch,
        link=TCLink
    )

    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
