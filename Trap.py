from pox.core import core
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr
import pox.openflow.libopenflow_01 as of
from datetime import datetime

def HTTP_handler():
    print("A HTTP request to the HoneyPot")

def SMB_handler():
    print("A SMB request to the HoneyPot")

def Honeypot(event):
    Received_packet = event.parsed.find('tcp')
    if Received_packet is None:
       return
    # search for tcp traffic, if it not tcp traffic forward it to the forwarding.l2_learning componenet
    elif Received_packet.dstport == 445 or Received_packet.dstport == 80:
    # match the destination ports with the ports 445 and 80
            IP = event.parsed.find('ipv4')
            ipaddr = IP.dstip
            if ipaddr == '10.0.0.6':
            # match the destination IP with the honeypot IP
                ip_packet = event.parsed.find('ipv4')
                ipaddr = IP.srcip
                print(ipaddr)
                detection_time = str(datetime.now())
                core.getLogger("blocker").debug("Blocked packet sent from %s to %i (The honeypot)", Received_packet.srcport, Received_packet.dstport)
                msg = of.ofp_flow_mod()
                msg.match.dl_type = 0x800
                msg.match.nw_src = ipaddr
                msg.match.nw_proto = 6
                msg.match.tp_dst = Received_packet.dstport
                msg.idle_timeout = 1200
                msg.hard_timeout = 1800
            # If the packet destinated to the honeypot, block the sender from sending any TCP traffic
                for connection in core.openflow.connections:
                    connection.send(msg)
                    core.getLogger("blocker").debug("installing flow for %s with destination port %i", ip_packet.srcip, Received_packet.dstport)
                    core.getLogger("blocker").debug("Blocked suspicious HTTP or SMB traffic %s <-> %s : BadRabbit self-propogation attempt", Received_packet.srcport, Received_packet.dstport)
                    print("Detection time is: ", detection_time)
                    
                    event.halt = True
            if Received_packet.dstport == 80:
               HTTP_handler()
            if Received_packet.dstport == 445: 
               SMB_handler()
    else:
        return
    # If the destination ports or the packet is not destinated to the honeypot, forward it to the forwarding.l2_learning
def launch():
    core.openflow.addListenerByName("PacketIn", Honeypot, priority=10000)

