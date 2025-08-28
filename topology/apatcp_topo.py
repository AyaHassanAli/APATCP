# apatcp_topo.py
# Defines Mininet-WiFi topology for APATCP with multi-controller SDN

from mininet.topo import Topo

class APATCPTopo(Topo):
    def build(self):
        print("Building APATCP topology...")

topos = {'apatcp': (lambda: APATCPTopo())}
