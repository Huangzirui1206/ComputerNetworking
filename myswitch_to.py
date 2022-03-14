'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''

'''
Add time-out feature according to the base of Ethernet learning switch.
'''

import switchyard
from switchyard.lib.userlib import *
import time

def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]

    macdict = {} # macdict is a dictionary of mac_address:[port_name,time.time()] 
                 # It works as a forwarding table.

    while True:
        try:
            _, fromIface, packet = net.recv_packet()
        except NoPackets:
            # Check whether forwarding table entries are out of time
            cur_time = time.time()
            for addr in list(macdict):
                if cur_time - macdict[addr][1] >= 10:
                    del macdict[addr]
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
        macdict[eth.src] = [fromIface,time.time()]

        if eth.dst in mymacs:
            # Drop the frame intended for self
            log_info("Received a packet intended for me")
        else:
            # Search macdict first. If eth.dst is found, forward frame exactly; otherwise flood.
            if eth.dst in macdict:
                for intf in my_interfaces:
                    if intf.name == macdict[eth.dst][0]:
                        log_info (f"Forwarding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)
                        break
            else:
                for intf in my_interfaces:
                    if fromIface!= intf.name:
                        log_info (f"Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)

    net.shutdown()
