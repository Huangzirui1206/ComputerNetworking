'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''

'''
Add the Least-Recently-Used rule to switch
'''

import switchyard
from switchyard.lib.userlib import *

'''
Use the combination of dictionary and list or an OrderedDict.
Here choose the first method.
Thus the LRU algorithm is O(1) in time capacity and O(n) in space compacity
'''
class LRUCache:
    def __init__(self, size=5):
        self.size = size
        self.dict = {}
        self.list = []

    def set(self, key, value):
        if key in self.dict:
            self.list.remove(key)
        elif len(self.dict) == self.size:
            lru_key = self.list.pop()
            # For deploying
            log_info(f"According to the LRU rule, {lru_key} is evicted out forwarding table.")
            self.dict.pop(lru_key)
        self.list.insert(0, key)
        self.dict[key] = value

    def get(self, key):
        if key in self.dict:
            self.list.remove(key)
            self.list.insert(0, key)
            return self.dict[key]
        else:
            return None



def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]

    macdict = LRUCache()

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
