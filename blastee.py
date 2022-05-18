#!/usr/bin/env python3

import time
import threading
from struct import pack
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Blastee:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasterIp,
            num
    ):
        log_info("Start Blastee")
        self.net = net
        self.blasterIp = blasterIp
        self.totnum = int(num)

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        log_debug(f"I got a packet from {fromIface}")
        log_debug(f"Pkt: {packet}")
        ackpkt = Ethernet() + IPv4() + UDP()
        ackpkt[0].src = "20:00:00:00:00:01"
        ackpkt[0].dst = "40:00:00:00:00:02"
        ackpkt[0].ethertype = EtherType.IPv4

        ackpkt[1].src = "192.168.200.1"
        ackpkt[1].dst = self.blasterIp
        ackpkt[1].ttl = 3
        ackpkt[1].protocol = IPProtocol.UDP

        ackpkt[2].src = 0
        ackpkt[2].dst = 0
        
        seqbyte = packet[3].to_bytes()[:4]
        lengthbyte = packet[3].to_bytes()[4:6]
        length =  struct.unpack(">H",lengthbyte)[0]
        payload = None
        if length < 8:
            payload = struct.pack(">II", 0, 0)[0]
        else:
            payload = packet[3].to_bytes()[6:14]
        rpc = RawPacketContents(seqbyte+payload)
        ackpkt.insert_header(3,rpc)

        self.net.send_packet(fromIface, ackpkt) 


    def start(self):
        '''A running daemon of the blastee.
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

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blastee = Blastee(net, **kwargs)
    blastee.start()
