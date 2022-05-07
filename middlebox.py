#!/usr/bin/env python3

import time
import threading
import random
from random import randint

import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Middlebox:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            dropRate="0.19"
    ):
        self.net = net
        self.dropRate = float(dropRate)

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        if fromIface == "middlebox-eth0":
            log_debug("Middlebox received from blaster")
            num = random.random()
            if num >= self.dropRate:
                log_debug("The blaster packet is transmited successfully")
                packet[0].dst = "20:00:00:00:00:01"
                packet[0].src = "40:00:00:00:00:01"
                packet[0].ethertype = EtherType.IPv4
                packet[1].ttl -= 1
                self.net.send_packet("middlebox-eth1", packet)
            else:
                log_debug("The blaster packet is lost")
        elif fromIface == "middlebox-eth1":
            log_debug(" Midflebox received from blastee")
            packet[0].dst = "10:00:00:00:00:01"
            packet[0].src = "40:00:00:00:00:01"
            packet[0].ethertype = EtherType.IPv4
            packet[1].ttl -= 1
            self.net.send_packet("middlebox-eth0", packet)
        else:
            log_debug("Oops :)")

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

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    middlebox = Middlebox(net, **kwargs)
    middlebox.start()
