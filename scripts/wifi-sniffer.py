#!/usr/bin/env python

import os
import sys
from datetime import datetime
from time import mktime
import csv
from scapy.all import *
import subprocess
from multiprocessing import Process
import signal
import threading
nearby_APs = {} #ssid->AP mac->[list of properties]
nearby_MACs = {}
probing_APs = {} #ssid->client mac->[list of properties]
monitored_APs = {}
monitored_APs['home24Ghz']=['e0:3f:49:f4:21:58']
filepath = '/var/www/html/wifilog/data/'

def outputData(probing_APs, nearby_APs):
	global last_refresh
	diff = mktime(datetime.now().timetuple()) - mktime(last_refresh.timetuple())
	
	if diff>refresh_int:
		if not is_startup:
			os.system("clear")
			print "Scan on %s interface running since %s, %i minutes in total (last update @ %s)" % (iface_name, start_time.strftime("%H:%M:%S, %d/%m/%Y"), (mktime(datetime.now().timetuple()) - mktime(start_time.timetuple()))/60, datetime.now().strftime("%H:%M:%S, %d/%m/%Y"))
				
		file_name = filepath+"log_wifi-sniffer-clients-"+start_time.strftime("%H-%M-%S-%d-%m-%Y")+".csv"
		f = open(file_name, "w+")
		writer = csv.writer(f)
		writer.writerow(("SSID", "SSID MAC", "Client MAC", "Connected?", "First seen", "Last seen"))
		
		nearby_clients = {}
		for ssid in probing_APs.keys():
			for client in probing_APs[ssid]:
				writer.writerow((ssid, probing_APs[ssid][client]["ap_mac"], client, probing_APs[ssid][client]["connected"], probing_APs[ssid][client]["firstseen"], probing_APs[ssid][client]["lastseen"]))
				tmp_Aps = set()
				if client in nearby_clients.keys():
					tmp_Aps = nearby_clients[client]
				tmp_Aps.add(ssid)
				nearby_clients[client] = tmp_Aps
				
		f.close()
		if not is_startup:
			print "\nClients log file saved to "+file_name
		
		file_name = filepath+"log_wifi-sniffer-APs-"+start_time.strftime("%H-%M-%S-%d-%m-%Y")+".csv"
		f = open(file_name, "w+")
		writer = csv.writer(f)
		writer.writerow(("SSID", "MAC", "Channel", "Security", "Hidden", "Rogue", "First seen", "Last seen"))
		
		rogue_APs = 0
		open_APs = set()
		for ssid in nearby_APs.keys():
			for mac in nearby_APs[ssid]:
				writer.writerow((ssid, mac, nearby_APs[ssid][mac]["channel"], nearby_APs[ssid][mac]["secured"], nearby_APs[ssid][mac]["hidden"], nearby_APs[ssid][mac]["rogue"], nearby_APs[ssid][mac]["firstseen"], nearby_APs[ssid][mac]["lastseen"]))
				if nearby_APs[ssid][mac]["rogue"]=="1":
					rogue_APs+=1
				if nearby_APs[ssid][mac]["secured"]=="0":
					open_APs.add(ssid)
		f.close()
		if not is_startup:
			print "Nearby APs log file saved to "+file_name
		
			print "\n* Total nearby APs: %i" % (len(nearby_APs))
			print "* Number of APs clients tried to associate with (or are connected to): %i" % (len(probing_APs))
			print "* Number of clients who tried to associate with different APs (or are connected to): %i" % (len(nearby_clients))
			print "* Potentially rogue APs: %i" % (rogue_APs)
			print "* Open access APs: %i" % (len(open_APs))
		
		last_refresh = datetime.now()

def channelHopper():
	while True:
		try:
			#switch channel		
			current_ch = random.randrange(1,13)
			proc = subprocess.Popen(['iw', 'dev', iface_name, 'set', 'channel', str(current_ch)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			time.sleep(0.5)
		except KeyboardInterrupt:
			break

def PacketHandler(pkt):
	global last_refresh
	
	if pkt.haslayer(Dot11) and (pkt.type==0 or pkt.type==2) and (pkt.subtype==4 or pkt.subtype==5 or pkt.subtype==8):
		#log any clients connected to nearby APs
		if pkt.type==2 and pkt.subtype==4:
			ap_mac = pkt.addr1
			client_mac = pkt.addr2
			clients = {}
			if ap_mac in nearby_MACs:
				ssid = nearby_MACs[ap_mac]
				
				if ssid in probing_APs.keys():
					clients = probing_APs[ssid]
					
				if client_mac not in clients.keys():
					clients[client_mac]={}
					clients[client_mac]['firstseen'] = datetime.now()
				
				clients[client_mac]['ap_mac'] = ap_mac
				clients[client_mac]['connected'] = '1'
				clients[client_mac]['lastseen'] = datetime.now()
				probing_APs[ssid] = clients
				
		#log any clients sending probe requests
		elif pkt.type==0 and pkt.subtype==4 and pkt.info:
			ssid = pkt.info
			mac = pkt.addr2
			
			clients = {}
			if ssid in probing_APs.keys():
				clients = probing_APs[ssid]
				
			if mac not in clients.keys():
				clients[mac]={}
				clients[mac]['firstseen'] = datetime.now()
				clients[mac]['connected'] = '0' #presumably, not known yet
				clients[mac]['ap_mac'] = '' #simply don't know
			
			clients[mac]['lastseen'] = datetime.now()
			probing_APs[ssid] = clients
				
		#log any probe or beacon responses
		elif pkt.type==0 and (pkt.subtype==5 or pkt.subtype==8) and pkt.info:
			ssid = pkt.info
			mac = pkt.addr2
			mac_details = {}
			if ssid in nearby_APs.keys():
				mac_details = nearby_APs[ssid]
					
			if mac not in mac_details.keys():
				mac_details[mac]={}
				mac_details[mac]['firstseen'] = datetime.now()
				
			mac_details[mac]['lastseen'] = datetime.now()
				
			#attempt to check for rogue AP
			if ssid in monitored_APs.keys() and mac not in monitored_APs[ssid]:
				mac_details[mac]['rogue'] = "1"
			else:
				mac_details[mac]['rogue'] = "0"
				
			#p = pkt[Dot11Elt]
			cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}""{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')
				
			if 'privacy' in cap:
				mac_details[mac]['secured'] = "1"
				#while isinstance(p, Dot11Elt):
					#if p.ID == 48:
					#	mac_details[mac]['security'] = "WPA2"
					#elif p.ID == 221 and p.info.startswith('\x00P\xf2\x01\x01\x00'):
					#	mac_details[mac]['security'] = "WPA"
					#p = p.payload
			else:
				mac_details[mac]['secured'] = "0"
					
			if ssid.startswith('\x00'):
				mac_details[mac]['hidden'] = "1"
			else:
				mac_details[mac]['hidden'] = "0"
					
			mac_details[mac]['channel'] = str(ord(pkt[Dot11Elt:3].info))
			nearby_APs[ssid] = mac_details
				
			#add MAC and AP to separate array that allows to match currently connected clients to AP by looking up AP mac address
			if mac not in nearby_MACs:
				nearby_MACs[mac] = ssid

		#outputData()
		do_logging = Process(target = outputData(probing_APs, nearby_APs))
		do_logging.start()

def stop_processes(signal, frame):
	channel_hop.terminate()
	channel_hop.join()
	do_logging.terminate()
	do_logging.join()

is_startup = False
for arg in sys.argv:
	if arg=="--startup":
		is_startup = True
		break

if not is_startup:	
	os.system("clear")
	print "\n----\n"
	print "Wi-Fi sniffer is a tool that allows you to see clients currently trying to connect to access points (APs) by sending probe requests."
	print "You can also see all APs in the proximity. Additionally, you can try to identify rogue APs as they appear (see monitored_APs)."
	print "N.B. - the program will hop wifi channels every 2 seconds to discover more APs nearby."
	print "\n----\n"
	print "To start with, let's set some parameters (alternatively you could have started the script with default values by using switch --startup \n"

	i_iface_name=raw_input("Interface to use (default: mon0):")
	iface_name = "mon0" if i_iface_name=="" else i_iface_name
	i_refresh_interval=raw_input("Refresh interval in seconds (default: 30):")
	refresh_int = 30 if i_refresh_interval=="" else int(i_refresh_interval)
else:
	iface_name = "mon0"
	refresh_int = 30
	
start_time = datetime.now()
last_refresh = datetime.now()

if not is_startup:
	print "\n----"
	print "Please wait %i seconds for initial results..." % (refresh_int)
	
do_logging = Process(target = outputData(probing_APs, nearby_APs))
do_logging.start()
channel_hop = Process(target = channelHopper)
channel_hop.start()
signal.signal(signal.SIGINT, stop_processes)
sniff(iface=iface_name, lfilter=lambda x: (x.haslayer(Dot11)), prn=PacketHandler, store=False)
