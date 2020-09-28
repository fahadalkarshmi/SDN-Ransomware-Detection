# SDN-Ransomware-Detection
Applications to detect BadRabbit ransomware, using POX controller and OpenvSwitch.

This work was established to obtain a Masters degree in Cybersecurity from 
The University of York, with financial support provided by Najran University. The applications are: 

1. Deep Packet Inspection, to detect unique strings that BadRabbit uses in SMB and HTTP communications. This code has been coded by Elpida Rouka (FB: https://www.facebook.com/elpida.ro.9), and has been modified by Fahad Alotaibi in regard to block the infected device based on the MAC address instead of the IP address, beside to use the BadRabbit unique strings instead of ExPetr strings.

2. ARP-based Detection of Scanning, to detect BadRabbit network enumeration, this code had been coded by Elpida Rouka. It is worth noting that this code does not work for BadRabbit properly, as their is a chance of BadRabbit self-propgating before the detection.

3. Header Packet Inspection, to block the attempts to use NTLMSSP 1.2. 

4. Packet size checker, to block BadRabbit propgating attempts using SMB, this application check each SMB packet size and store it in an array. And when the suspicious packets are more than three, the suspicious device is blocked.

5. Trap, this application based on the assumption that their is a trap in the network hold the IP 10.0.0.6, and any attempt to communicate with this device through the ports 80 and 445 is considered suspicious.

To run these codes, you must implement an SDN testbed which has POX utility as a controller, and OpenvSwitch as SDN data plane.

For further information, u can contact me on twitter: @FahadAlkarshmi
