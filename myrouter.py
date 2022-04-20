#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *
import ipaddress

class ARPCache(object): # static 
    def __init__(self, timeout = 180):
        self.timeout = timeout
        self.cache = {} # Ipaddr:[hwaddr,timestamp] 
        
    def put(self, key, value, timestamp = -1): # The default entry type is static
        log_info(f"The cache puts in entry {key} -- {value}")
        self.cache[IPv4Address(key)] = value

    def get(self, key): # Attention to the type traslation
        return self.cache.get(IPv4Address(key))

class ForwardingTable(object):  #static forwarding table
    def __init__(self):
        self.dict = {}
    
    def put_entry(self, ipaddr, netmask, nexthop, intf):
        ipaddr_num = int(IPv4Address(ipaddr))
        netmask_num = int(IPv4Address(netmask))
        prefix = ipaddr_num & netmask_num
        self.dict[IPv4Address(ipaddr)] = {'prefix':prefix, 'netmask_num':netmask_num, 'nexthop':nexthop, 'intf':intf}

    def prefix_match(self, destaddr):
        destaddr = IPv4Address(destaddr)
        destaddr_num = int(destaddr)
        # Considering the longest prefix matching rule
        matched_key = None
        for key in self.dict:
            matched = destaddr_num & self.dict[key]['netmask_num'] == self.dict[key]['prefix']
            if matched: # prefix matched
                if destaddr == key: # destiantion is this router, drop the packet at this stage
                    return None,None
                else:   # longest prefix matching rule
                    if matched_key == None or self.dict[key]['netmask_num'] > self.dict[matched_key]['netmask_num']:
                        matched_key = key
        if matched_key != None:
            return self.dict[matched_key]['intf'], self.dict[matched_key]['nexthop']
        else:
            return None,None # None means the packet is destinied at this router or somewhere disconnected from this router


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.arpCache = ARPCache()
        self.forwardingTable = ForwardingTable()
        self.ipqueue = []
        for intf in self.net.interfaces():
            # Record own ip/ethernet addrs in arp table
            self.arpCache.put(intf.ipaddr, intf.ethaddr)
            # Add the interface information into forwarding table
            self.forwardingTable.put_entry(intf.ipaddr, intf.netmask, '0.0.0.0', intf)
        # read information from forwarding_table.txt
        for line in open("forwarding_table.txt","r"): 
            str_list = line.split()
            self.forwardingTable.put_entry(str_list[0],str_list[1],str_list[2],self.name_in_router(str_list[3]))
            
    def send_arpRequest(self, targetprotoaddr):
        forwardIntf , nexthop = self.forwardingTable.prefix_match(targetprotoaddr)
        if forwardIntf is not None:
            senderhwaddr = forwardIntf.ethaddr
            senderprotoaddr = forwardIntf.ipaddr
            pkt = create_ip_arp_request(senderhwaddr, senderprotoaddr, targetprotoaddr)
            self.net.send_packet(forwardIntf, pkt)
            log_info(f"Sending arp request succeeded from {senderprotoaddr} to {targetprotoaddr}")
            return True
        else:
            log_info(f"Sending arp request failed with targetprotoaddr is {targetprotoaddr}")
            return False

    def forward_ippacket(self, packet, cnt, last_time = 0):
        ipheader = packet.get_header(IPv4, None)
        if ipheader is None:
            return  -1 # Packet has no ip header, drop it. 
        # prefix match to get the forwarding interface
        forwardIntf , nexthop = self.forwardingTable.prefix_match(ipheader.dst)
        if forwardIntf is None:
            log_info(f"The ipaddr {ipheader.dst} is not connected to the router or just in the router.")
            return -1
        # First check whether the targetprotoaddr is in the ARPCache
        if nexthop == '0.0.0.0': # next hop is destination
            nexthop = ipheader.dst
        targethwaddr = self.arpCache.get(nexthop)
        if targethwaddr == None:
            if time.time()-last_time < 1:
                return cnt
            elif cnt >= 5:
                return -1 # drop packet
            else: # The hwaddr not recorded in arpCache need an arp request
                # send arp request  
                flag = self.send_arpRequest(nexthop)
                if flag: # If the arp request is sended successfully
                    # put entry into ipqueue and wait for arp reply
                    # At this stage the packet has no data
                    return cnt+1
                else:
                    return -1 # in case of accidental failure
        else: # The targethwaddr has already been in the arp cache
            ipheader.ttl = ipheader.ttl - 1 # TTL decreace 
            # At this stage, just assume the TTL will not be expired
            # Create the etherheader for ipv4 packet
            etherheader = Ethernet(src = forwardIntf.ethaddr, dst = targethwaddr, ethertype = EtherType.IPv4)
            # create packet and send it 
            packet[0] = etherheader
            packet[1] = ipheader
            self.net.send_packet(forwardIntf, packet)
            return -1

    def ipaddr_in_router(self, targetprotoaddr):
        for intf in self.net.interfaces():
            if intf.ipaddr == targetprotoaddr:
                return intf
        return None
    
    def name_in_router(self, name):
        for intf in self.net.interfaces():
            if intf.name == name:
                return intf
        return None

    def fresh_ipqueue(self):
        for item in self.ipqueue:
            cnt = self.forward_ippacket(item['packet'],item['cnt'],item['time'])
            if item['cnt'] != cnt:
                item['time'] = time.time()
                item['cnt'] = cnt
        self.ipqueue = list(filter(lambda item:item['cnt'] != -1, self.ipqueue))

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        log_info(f'pkt is {str(packet)}')
        arp = packet.get_header(Arp, None)
        if arp is not None:   # Handle ARP packets
            log_info(f"This is an ARP packet, its arp header is {arp}")
            # self-learning
            # Use arpCache as a static table, so no need to refresh.
            # put the sender ipaddr--ethaddr into cache
            self.arpCache.put(arp.senderprotoaddr, arp.senderhwaddr)
            # Forward ARP packet
            if arp.operation == ArpOperation.Request:
                targetIntf = self.ipaddr_in_router(arp.targetprotoaddr)
                if targetIntf is not None:
                    pkt = create_ip_arp_reply(targetIntf.ethaddr, arp.senderhwaddr, targetIntf.ipaddr, arp.senderprotoaddr) 
                    self.net.send_packet(self.name_in_router(ifaceName), pkt)
            elif arp.operation == ArpOperation.Reply: 
                pass
        else:   # Forward packets by forwarding table
            cnt = self.forward_ippacket(packet, 0, 0)
            if cnt != -1:
                self.ipqueue.append({'packet':packet, 'time':time.time(), 'cnt':cnt})
         


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
            else:
                self.handle_packet(recv)
            finally:
                self.fresh_ipqueue()

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

