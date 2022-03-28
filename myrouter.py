#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *
import time

class ARPCache(object):
    def __init__(self, timeout = 180):
        self.timeout = timeout
        self.cache = {} # Ipaddr:[hwaddr,timestamp] 
                        # If timestamp is negative, the entry is static
                        # Otherwise it's dynamic.
    
    def put(self, key, value, timestamp = -1): # The default entry type is static
        log_info(f"The cache puts in entry {key} -- {value}")
        self.cache[key] = [value,timestamp]

    def get(self, key):
        if key in self.cache:
            if self.cache[key][1] != -1:
                self.cache[key][1] = time.time()
            return self.cache[key][0]
        else:
            return None
    
    def refresh():  # Evict those dynamic entries that are out of time
        cur_time = time.time()
        for key in list(self.cache):
            if cur_time - self.cache[key][1] >= self.timeout:
                log_info(f"The entry \"{key}:{self.cache[key]}\" is evicted At time {cur_time}")
                del self.cache[key]


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.arpCache = ARPCache()
        # Record own ip/ethernet addr
        for intf in self.net.interfaces():
            self.arpCache.put(intf.ipaddr, intf.ethaddr)

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        arp = packet.get_header(Arp, None)
        log_info(f"The arp is {arp}")
        if arp is not None:   # Handle ARP packets
            # self-learning
            # Use arpCache as a static table, so no need to refresh.
            # put the sender ipaddr--etheraddr into cache
            self.arpCache.put(arp.senderprotoaddr, arp.senderhwaddr)
            # Forward ARP packet
            if arp.operation == ArpOperation.Request:
                # Search the cache to see whether the targethwaddr is already in cache
                targethwaddr = self.arpCache.get(arp.targetprotoaddr)
                if targethwaddr == None: # The targethwaddr is not in the cache
                    forwardIntf = None
                    try:
                        forwardIntf = self.net.interface_by_ipaddr(arp.targetprotoaddr) # Get the forwarding interface.
                        pkt = create_ip_arp_request(arp.senderhwaddr, arp.senderprotoaddr, arp.targetprotoaddr)
                        self.net.send_packet(forwardIntf, pkt)
                    except KeyError:
                        # The target ipaddr is not combined to any interface, just drop it.
                        log_info(f"The ipaddr {arp.targetprotoaddr} is not connected to the router.")
                        pass
                else:   # The targethwaddr is already in the cache
                    pkt = create_ip_arp_reply(targethwaddr, arp.senderhwaddr, arp.targetprotoaddr, arp.senderprotoaddr)
                    for forwardIntf in self.net.interfaces():
                        if forwardIntf.name == ifaceName:
                            self.net.send_packet(forwardIntf, pkt)
                            break
            elif arp.operation == ArpOperation.Reply: # Handle ARP Reply, but drop them for now according to the document
                pass
        else:   # Drop all kinds of other packets for now
            pass       



    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.stop()

    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()
