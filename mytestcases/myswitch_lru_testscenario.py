from switchyard.lib.userlib import *

'''
    20: ~ :01   eth0    a
    30: ~ :02   eth1    b
    20: ~ :03   eth2    c
    30: ~ :04   eth3    d
    40: ~ :05   eth4    e
    20: ~ :05   eth0    f
'''

'''
1.  b broadcasts;    (b)
2.  a to b  (b,a)
    b to a  (a,b)
3.  c to b  (b,c,a)
    b to c  (c,b,a)
4.  c to d  (c,b,a) *flood
    d to c  (c,d,b,a)
5.  e to b  (b,e,c,d,a)
    b to e  (e,b,c,d,a)
6.  f to e  (e,f,b,c,d)
    e to f  (f,e,b,c,d)
7.  b to a  (b,f,e,c,d)*a is out of table, flood.
    a to b  (b,a,f,e,c)
8.  f to d  (f,b,a,e.c)*d is out of table, flood.
    d to f  (f,d,b,a,e)
'''

'''
Testcases for least_recently_used switch
Set the default forwarding table size to 5
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
    s.add_interface('eth3', '10:00:00:00:00:04')
    s.add_interface('eth4', '10:00:00:00:00:05')

    # test case 1: a frame with broadcast destination should get sent out
    # all ports except ingress
    testpkt = new_packet(
        "30:00:00:00:00:02",
        "ff:ff:ff:ff:ff:ff",
        "202.0.0.32",
        "255.255.255.255"
    )
    s.expect(
        PacketInputEvent("eth1", testpkt, display=Ethernet),
        ("An Ethernet frame with a broadcast destination address "
         "should arrive on eth1")
    )

    s.expect(
        PacketOutputEvent("eth0", testpkt, "eth2", testpkt,"eth3", testpkt, "eth4", testpkt, display=Ethernet),
        ("The Ethernet frame with a broadcast destination address should be "
         "forwarded out ports eth0, eth2, eth3 and eth4")
    )

    # test case 2: a frame with any unicast address except one assigned to hub
    # interface should be sent out all ports except ingress
    # The destination port is in the forwarding table.
    reqpkt = new_packet(
        "20:00:00:00:00:01",
        "30:00:00:00:00:02",
        '202.0.0.21',
        '202.0.0.32'
    )
    s.expect(
        PacketInputEvent("eth0", reqpkt, display=Ethernet),
        ("An Ethernet frame from 20:00:00:00:00:01 to 30:00:00:00:00:02 "
         "should arrive on eth0")
    )
    s.expect(
        PacketOutputEvent("eth1", reqpkt,  display=Ethernet),
        ("Ethernet frame destined for 30:00:00:00:00:02 should be forwarding"
         " out eth1 after self-learning")
    )

    resppkt = new_packet(
        "30:00:00:00:00:02",
        "20:00:00:00:00:01",
        '202.0.0.32',
        '202.0.0.21',
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

    # test case 3   (c,b),(b,c)
    reqpkt = new_packet(
        "20:00:00:00:00:03",
        "30:00:00:00:00:02",
        '202.0.0.23',
        '202.0.0.32'
    )
    s.expect(
        PacketInputEvent("eth2", reqpkt, display=Ethernet),
        ("An Ethernet frame from 20:00:00:00:00:03 to 30:00:00:00:00:02 "
         "should arrive on eth2")
    )
    s.expect(
        PacketOutputEvent("eth1", reqpkt,  display=Ethernet),
        ("Ethernet frame destined for 30:00:00:00:00:02 should be forwarding"
         " out eth1 after self-learning")
    )

    resppkt = new_packet(
        "30:00:00:00:00:02",
        "20:00:00:00:00:03",
        '202.0.0.32',
        '202.0.0.23',
        reply=True
    )
    s.expect(
        PacketInputEvent("eth1", resppkt, display=Ethernet),
        ("An Ethernet frame from 30:00:00:00:00:02 to 20:00:00:00:00:01 "
         "should arrive on eth1")
    )
    s.expect(
        PacketOutputEvent("eth2", resppkt, display=Ethernet),
        ("Ethernet frame destined to 20:00:00:00:00:01 should be forwarding out "
         "interface eth0")
    )

    # test case 4: (c,d),(d,c)
    reqpkt = new_packet(
        "20:00:00:00:00:03",
        "30:00:00:00:00:04",
        '202.0.0.23',
        '202.0.0.34'
    )
    s.expect(
        PacketInputEvent("eth2", reqpkt, display=Ethernet),
        ("An Ethernet frame from 20:00:00:00:00:03 to 30:00:00:00:00:04 "
         "should arrive on eth2")
    )
    s.expect(
        PacketOutputEvent("eth0", reqpkt, "eth1", reqpkt, "eth3", reqpkt, "eth4", reqpkt, display=Ethernet),
        ("The Ethernet frame with address 30:00:00:00:00:04 is not in the table, and should be "
         "forwarded out ports eth0, eth1, eth3 and eth4")
    )

    resppkt = new_packet(
        "30:00:00:00:00:04",
        "20:00:00:00:00:03",
        '202.0.0.34',
        '202.0.0.23',
        reply=True
    )
    s.expect(
        PacketInputEvent("eth3", resppkt, display=Ethernet),
        ("An Ethernet frame from 30:00:00:00:00:04 to 20:00:00:00:00:03 "
         "should arrive on eth3")
    )
    s.expect(
        PacketOutputEvent("eth2", resppkt, display=Ethernet),
        ("Ethernet frame destined to 20:00:00:00:00:03 should be forwarding out "
         "interface eth2")
    )


    # test case 5: (e,b),(b,e)
    reqpkt = new_packet(
        "40:00:00:00:00:05",
        "30:00:00:00:00:02",
        '202.0.0.45',
        '202.0.0.32'
    )
    s.expect(
        PacketInputEvent("eth4", reqpkt, display=Ethernet),
        ("An Ethernet frame from 40:00:00:00:00:05 to 30:00:00:00:00:02 "
         "should arrive on eth4")
    )
    s.expect(
        PacketOutputEvent("eth1", reqpkt, display=Ethernet),
        ("Ethernet frame destined to 30:00:00:00:00:02 should be forwarding out "
         "interface eth1")
    )

    resppkt = new_packet(
        "30:00:00:00:00:02",
        "40:00:00:00:00:05",
        '202.0.0.34',
        '202.0.0.23',
        reply=True
    )
    s.expect(
        PacketInputEvent("eth1", resppkt, display=Ethernet),
        ("An Ethernet frame from 30:00:00:00:00:02 to 40:00:00:00:00:05 "
         "should arrive on eth1")
    )
    s.expect(
        PacketOutputEvent("eth4", resppkt, display=Ethernet),
        ("Ethernet frame destined to 40:00:00:00:00:05 should be forwarding out "
         "interface eth4")
    )


    # test case 6: (f,e),(e,f)
    reqpkt = new_packet(
        "20:00:00:00:00:05",
        "40:00:00:00:00:05",
        '202.0.0.25',
        '202.0.0.45'
    )
    s.expect(
        PacketInputEvent("eth0", reqpkt, display=Ethernet),
        ("An Ethernet frame from 20:00:00:00:00:05 to 40:00:00:00:00:05 "
         "should arrive on eth0")
    )
    s.expect(
        PacketOutputEvent("eth4", reqpkt, display=Ethernet),
        ("Ethernet frame destined to 40:00:00:00:00:05 should be forwarding out "
         "interface eth4")
    )

    resppkt = new_packet(
        "40:00:00:00:00:05",
        "20:00:00:00:00:05",
        '202.0.0.45',
        '202.0.0.25',
        reply=True
    )
    s.expect(
        PacketInputEvent("eth4", resppkt, display=Ethernet),
        ("An Ethernet frame from 40:00:00:00:00:05 to 20:00:00:00:00:05 "
         "should arrive on eth4")
    )
    s.expect(
        PacketOutputEvent("eth0", resppkt, display=Ethernet),
        ("Ethernet frame destined to 20:00:00:00:00:05 should be forwarding out "
         "interface eth0")
    )

    # test case 7: (b,a),(a,b) * a is out of table
    reqpkt = new_packet(
        "30:00:00:00:00:02",
        "20:00:00:00:00:01",
        '202.0.0.32',
        '202.0.0.21'
    )
    s.expect(
        PacketInputEvent("eth1", reqpkt, display=Ethernet),
        ("An Ethernet frame from 30:00:00:00:00:02 to 20:00:00:00:00:01 "
         "should arrive on eth1")
    )
    s.expect(
        PacketOutputEvent("eth0", reqpkt, "eth2", reqpkt, "eth3", reqpkt, "eth4", reqpkt, display=Ethernet),
        ("The Ethernet frame with address 20:00:00:00:00:01 is not in the table, and should be "
         "forwarded out ports eth0, eth2, eth3 and eth4")
    )

    resppkt = new_packet(
        "20:00:00:00:00:01",
        "30:00:00:00:00:02",
        '202.0.0.21',
        '202.0.0.32',
        reply=True
    )
    s.expect(
        PacketInputEvent("eth0", resppkt, display=Ethernet),
        ("An Ethernet frame from 20:00:00:00:00:01 to 30:00:00:00:00:02 "
         "should arrive on eth0")
    )
    s.expect(
        PacketOutputEvent("eth1", resppkt, display=Ethernet),
        ("Ethernet frame destined to 30:00:00:00:00:02 should be forwarding out "
         "interface eth1")
    )

    # test case 8: (f,d),(d,f) * d is out of table
    reqpkt = new_packet(
        "20:00:00:00:00:05",
        "30:00:00:00:00:04",
        '202.0.0.25',
        '202.0.0.34'
    )
    s.expect(
        PacketInputEvent("eth0", reqpkt, display=Ethernet),
        ("An Ethernet frame from 20:00:00:00:00:05 to 30:00:00:00:00:04 "
         "should arrive on eth0")
    )
    s.expect(
        PacketOutputEvent("eth1", reqpkt, "eth2", reqpkt, "eth3", reqpkt, "eth4", reqpkt, display=Ethernet),
        ("The Ethernet frame with address 30:00:00:00:00:04 is not in the table, and should be "
         "forwarded out ports eth1, eth2, eth3 and eth4")
    )

    resppkt = new_packet(
        "30:00:00:00:00:04",
        "20:00:00:00:00:05",
        '202.0.0.34',
        '202.0.0.25',
        reply=True
    )
    s.expect(
        PacketInputEvent("eth3", resppkt, display=Ethernet),
        ("An Ethernet frame from 30:00:00:00:00:04 to 20:00:00:00:00:05 "
         "should arrive on eth3")
    )
    s.expect(
        PacketOutputEvent("eth0", resppkt, display=Ethernet),
        ("Ethernet frame destined to 20:00:00:00:00:05 should be forwarding out "
         "interface eth0")
    )

    
    return s


scenario = test_switch()
