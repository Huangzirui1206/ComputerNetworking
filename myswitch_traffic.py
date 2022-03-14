'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import switchyard
from switchyard.lib.userlib import *

'''
Evict entries according to least_traffic_volume rule.
Define class LTVCache to realise this function.
self.ndict  'address:interface_name'
self.vdict  'address:traffic_volume'
'''
class LTVCache:
    def __init__(self, size = 5):
        self.ndict = {}
        self.vdict = {}
        self.size = size
    
    def set(self, key, value):
        if key in self.ndict:
            if self.ndict[key] !=  value:
                self.ndict[key] = value
                self.vdict[key] = 0
        else:
            if len(self.ndict) >= self.size:
                min_key = min(self.vdict, key = lambda k:self.vdict[k])
                self.ndict.pop(min_key)
                self.vdict.pop(min_key)
            self.ndict[key] = value
            self.vdict[key] = 0

    def get(self, key):
        if key in self.ndict:
            self.vdict[key] += 1
            return self.ndict[key]
        else:
            return None
            


def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]

    macdict = LTVCache()    # It works as a forwarding table.

    while True:
        try:
            _, fromIface, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            break

        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return
    
        # Record the source address.
        log_info (f"Receive packet {packet} from {fromIface}, record it in macdict")
        macdict.set(eth.src, fromIface)

        if eth.dst in mymacs:
            # Drop the frame intended for self
            log_info("Received a packet intended for me")
        else:
            # Search macdict first. If eth.dst is found, forward frame exactly; otherwise flood.
            outIntf = macdict.get(eth.dst)
            if outIntf != None:
                for intf in my_interfaces:
                    if intf.name == outIntf:
                        log_info (f"Forwarding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)
                        break
            else:
                for intf in my_interfaces:
                    if fromIface!= intf.name:
                        log_info (f"Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)

    net.shutdown()
