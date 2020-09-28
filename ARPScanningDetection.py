from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr
from datetime import datetime
mydict = dict()


def arp_handler(event): 
    packet = event.parsed 
    if packet.type == packet.ARP_TYPE:
    # if the packet is ARP, go to the next step
       if packet.payload.protosrc == IPAddr("0.0.0.0"):
          return
    # if the packet is destinated to 0.0.0.0 ignore it
       if packet.payload.opcode == arp.REQUEST: 
          mydict[packet.src] = mydict.get(packet.src, 0) + 1
          print packet.payload.protosrc, "has performed", mydict[packet.src], "unanswered ARP reuqests."
    # if the packet is request, register the MAC address in mydict dictonary and increase the thershold by one.
          if mydict[packet.src] > 5:
             ip_src = packet.src
             msg = of.ofp_flow_mod()
             msg.match.dl_src = packet.src
             msg.idle_timeout = 1800
             msg.hard_timeout = 1800
             for connection in core.openflow.connections:
                 connection.send(msg)
                 core.getLogger("ARP Requests monitor").debug("Blocked host with IP %s on port %i for 30 minutes", packet.payload.protosrc ,event.port)
                 detect_time = str(datetime.now())
                 print("Detection time is : ", detect_time)
             event.halt = True
    # if the thershold reached five, block the source MAC address from communicating within the network.
          else:
              pass
   # if the thershold does not reach five, forward the packet.
       elif packet.payload.opcode == arp.REPLY:
           mydict[packet.dst] = mydict.get(packet.dst, 0) - 1
           print packet.payload.protodst, "has performed", mydict[packet.dst], "unanswered ARP requests."
   # if the packet is reply, decrease one to the MAC source address
       else:
           return
    else: 
         return

def launch():
    mydict.clear()
    core.openflow.addListenerByName("PacketIn", arp_handler, priority = 20000)
