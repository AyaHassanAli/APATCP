from mininet.topo import Topo

class APATCPTopo(Topo):
    def build(self):
        print("Building APATCP topology")

topos = {'apatcp': (lambda: APATCPTopo())}
