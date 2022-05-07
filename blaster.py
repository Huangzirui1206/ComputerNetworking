#!/usr/bin/env python3

import time
from random import randint
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Blaster:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasteeIp,
            num,
            length="100",
            senderWindow="5",
            timeout="300",
            recvTimeout="100"
    ):
        self.net = net
        # arguments
        self.blasteeIp = blasteeIp
        self.totnum = int(num)
        self.length = int(length)
        self.senderWindowLenth = int(senderWindow)
        self.timeout = float(timeout)/1000
        self.recvTimeout = float(recvTimeout)/1000
        # for priting stats
        self.initTime = time.time()
        self.reTXnum = 0
        self.timeoutnum = 0
        self.throughput = 0
        self.goodput = 0
        # for snederWindow
        self.lhs = 0
        self.rhs = -1
        self.window = [None]*self.senderWindowLenth
        # for round timing
        self.roundTime = time.time()


    def print_stats(self):
        totTime = time.time() - self.initTime
        log_info(f"Total TX time(in seconds): {round(totTime,3)}")
        log_info(f"Number of reTx: {self.reTXnum}")
        log_info(f"Number of coarse TOs: {self.timeoutnum}")
        log_info(f"Throughput(Bps): {round(self.throughput/totTime,3)}")
        log_info(f"Goodput(Bps): {round(self.goodput/totTime,3)}")


    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        log_debug("I got a packet")
        seqbyte = packet[3].to_bytes()[:4]
        seqnum = struct.unpack(">I",seqbyte)[0]
        if seqnum < self.lhs or seqnum > self.rhs:
            return 
        else:
            wbase = self.lhs % self.senderWindowLenth
            widx = (seqnum - self.lhs + wbase) % self.senderWindowLenth
            if self.window[widx] is not None:
                self.window[widx] = None
                self.roundTime = time.time()
                self.totnum -= 1
                while self.lhs < self.rhs:
                    if self.window[self.lhs % self.senderWindowLenth] is None:
                        self.lhs += 1
                    else:
                        break

    def handle_no_packet(self):
        log_debug("Didn't receive anything")
        if self.totnum == 0:
            self.totnum = -1
            self.print_stats()
            return
        elif self.totnum < 0:
            return

        intf = self.net.interface_by_name("blaster-eth0")

        # Window is full but time is not out -- just wait
        if self.rhs - self.lhs + 1 == self.senderWindowLenth:
            if time.time() - self.roundTime < self.timeout:
                return
            else:
                for item in self.window:
                    if item is None:
                        continue
                    else:
                        self.reTXnum += 1
                        self.throughput += item.size()
                        self.net.send_packet(intf, item)
                self.roundTime = time.time()
                self.timeoutnum += 1
                return 

        # Creating the headers for the packet
        pkt = Ethernet() + IPv4() + UDP()
        pkt[0].src = "10:00:00:00:00:01"
        pkt[0].dst = "40:00:00:00:00:01"
        pkt[0].ethertype = EtherType.IP

        pkt[1].src = "192.168.100.1"
        pkt[1].dst = self.blasteeIp
        pkt[1].ttl = 3
        pkt[1].protocol = IPProtocol.UDP

        pkt[2].src = 0
        pkt[2].dst = 0

        self.rhs += 1
        seqstr = struct.pack(">I",self.rhs)
        lengthstr = struct.pack(">H",self.length)
        payload = bytes().zfill(self.length)
        rpc = RawPacketContents(seqstr + lengthstr + payload)
        pkt.insert_header(3,rpc)

        self.throughput += pkt.size()
        self.goodput += pkt.size()
        self.net.send_packet(intf, pkt)
        wbase = self.lhs % self.senderWindowLenth
        widx = (self.rhs - self.lhs + wbase) % self.senderWindowLenth
        self.window[widx] = pkt
        self.roundTime = time.time()



    def start(self):
        '''A running daemon of the blaster.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=self.recvTimeout)
            except NoPackets:
                self.handle_no_packet()
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blaster = Blaster(net, **kwargs)
    blaster.start()
