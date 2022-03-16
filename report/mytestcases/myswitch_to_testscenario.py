from switchyard.lib.userlib import *

'''
            20:~:01 / 192.168.1.100
            eth0
          /     \
         /       \
    eth1         eth2 40:~:03
    30:~:02           202.36.72.6
    172.16.42.2
'''

'''
Suppose the time limits is 10 seconds.
'''

def new_packet(hwsrc, hwdst, ipsrc, ipdst, reply=False):
    ether = Ethernet(src=hwsrc, dst=hwdst, ethertype=EtherType.IP)
    ippkt = IPv4(src=ipsrc, dst=ipdst, protocol=IPProtocol.ICMP, ttl=32)
    icmppkt = ICMP()
    if reply:
        icmppkt.icmptype = ICMPType.EchoReply
    else:
        icmppkt.icmptype = ICMPType.EchoRequest
    return ether + ippkt + icmppkt


def test_switch():
    s = TestScenario("hub tests")
    s.add_interface('eth0', '10:00:00:00:00:01')
    s.add_interface('eth1', '10:00:00:00:00:02')
    s.add_interface('eth2', '10:00:00:00:00:03')

    # test case 1: a frame with broadcast destination should get sent out
    # all ports except ingress
    testpkt = new_packet(
        "30:00:00:00:00:02",
        "ff:ff:ff:ff:ff:ff",
        "172.16.42.2",
        "255.255.255.255"
    )
    s.expect(
        PacketInputEvent("eth1", testpkt, display=Ethernet),
        ("An Ethernet frame with a broadcast destination address "
         "should arrive on eth1")
    )
        ### 
        #The forwarding table:
        #30, eth1
        ###

    s.expect(
        PacketOutputEvent("eth0", testpkt, "eth2", testpkt, display=Ethernet),
        ("The Ethernet frame with a broadcast destination address should be "
         "forwarded out ports eth0 and eth2")
    )

    # test case 2: a frame with any unicast address except one assigned to hub
    # interface should be sent out all ports except ingress
    # The destination port is in the forwarding table.
    reqpkt = new_packet(
        "20:00:00:00:00:01",
        "30:00:00:00:00:02",
        '192.168.1.100',
        '172.16.42.2'
    )
    s.expect(
        PacketInputEvent("eth0", reqpkt, display=Ethernet),
        ("An Ethernet frame from 20:00:00:00:00:01 to 30:00:00:00:00:02 "
         "should arrive on eth0")
    )
        ###
        #The forwarding table:
        #30, eth1   0s
        #20, eth0   0s
        ###
    s.expect(
        PacketOutputEvent("eth1", reqpkt,  display=Ethernet),
        ("Ethernet frame destined for 30:00:00:00:00:02 should be forwarding"
         "through out eth1")
    )

    resppkt = new_packet(
        "30:00:00:00:00:02",
        "20:00:00:00:00:01",
        '172.16.42.2',
        '192.168.1.100',
        reply=True
    )
    s.expect(
        PacketInputEvent("eth1", resppkt, display=Ethernet),
        ("An Ethernet frame from 30:00:00:00:00:02 to 20:00:00:00:00:01 "
         "should arrive on eth1")
    )
    s.expect(
        PacketOutputEvent("eth0", resppkt, display=Ethernet),
        ("Ethernet frame destined to 20:00:00:00:00:01 should be forwarding out "
         "interface eth0")
    )

    # Wait for 6 seconds
    s.expect(
        PacketInputTimeoutEvent(6.0),
        ("Sleep for 6 seconds.")
    )
        ###
        #The forwarding table:
        #30, eth1   6s
        #20, eth0   6s
        ###

    # test case 3: 
    reqpkt = new_packet(
        "40:00:00:00:00:03",
        "20:00:00:00:00:01",
        '202.36.72.6',
        '192.168.1.100',
    )
    s.expect(
        PacketInputEvent("eth2", reqpkt, display=Ethernet),
        ("An Ethernet frame from 40:00:00:00:00:03 to 20:00:00:00:00:01 "
         "should arrive on eth2")
    )
    s.expect(
        PacketOutputEvent("eth0", reqpkt, display=Ethernet),
        ("Ethernet frame destined to 20:00:00:00:00:01 should be forwarding out"
         " interface eth0")
    )

    resppkt = new_packet(
        "20:00:00:00:00:01",
        "40:00:00:00:00:03",
        '192.168.1.100',
        '202.36.72.6',
        reply=True
    )
    s.expect(
       PacketInputEvent("eth0", resppkt, display=Ethernet),
        ("An Ethernet frame from 20:00:00:00:00:01 to 40:00:00:00:00:03 "
         " should arrive on eth0")
    )
        ###
        #The forwarding table:
        #30, eth1   6s
        #20, eth0   0s
        #40, eth2   0s
        ###
    s.expect(
        PacketOutputEvent("eth2", resppkt, display=Ethernet),
        ("Ethernet frame destined to 40:00:00:00:00:03 should be forwarding out"
         " interface eth2")
    )


    # Wait for 6 seconds
    s.expect(
        PacketInputTimeoutEvent(6.0),
        ("Sleep for 6 seconds.")
    )
        ###
        #The forwarding table:
        #30, eth1   12s (remove)
        #20, eth0   6s
        #40, eth2   6s
        ###


    # test case 4: a frame with any unicast address except one assigned to hub
    # interface should be sent out all ports except ingress
    # The destination port is in the forwarding table.
    reqpkt = new_packet(
        "40:00:00:00:00:03",
        "30:00:00:00:00:02",
        '202.36.72.6',
        '192.168.1.100'
    )
    s.expect(
        PacketInputEvent("eth2", reqpkt, display=Ethernet),
        ("An Ethernet frame from 40:00:00:00:00:03 to 30:00:00:00:00:02 "
         "should arrive on eth2")
    )
    s.expect(
        PacketOutputEvent("eth0", reqpkt,"eth1", reqpkt,  display=Ethernet),
        ("Ethernet frame destined for 30:00:00:00:00:02 should be flooding "
         "out eth0 and eth1")
    )
        ###
        #The forwarding table:
        #30, eth1   0s
        #20, eth0   6s
        #40, eth2   0s
        ###
    resppkt = new_packet(
        "30:00:00:00:00:02",
        "40:00:00:00:00:03",
        '192.168.1.100',
        '202.36.72.6',
        reply=True
    )
    s.expect(
        PacketInputEvent("eth1", resppkt, display=Ethernet),
        ("An Ethernet frame from 30:00:00:00:00:02 to 40:00:00:00:00:03 "
         "should arrive on eth1")
    )
    s.expect(
        PacketOutputEvent("eth2", resppkt, display=Ethernet),
        ("Ethernet frame destined to 40:00:00:00:00:03 should be forwarding out"
         " interface eth0")
    )
    
    return s


scenario = test_switch()
