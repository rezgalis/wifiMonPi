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
probing_APs = {} #client mac->ssid->[list of properties]
monitored_APs = {}
monitored_APs['mySSID']=['00:00:00:00:00:00']
filepath = '/home/pi/scripts/wifi-sniffer/'
prev_channels = [] #list of channels that we switched to earlier - excluded by default to avoid hoping to same channels when using random()
nearby_ap_channels = set() #set of channels used by nearby APs - these are not excluded in random() when selecting channel to hop to - increasing chances of spotting connected clients
deauth_receiving_APs = {} #set of APs that we have detected deauth frames for


def outputData(probing_APs, nearby_APs):
	global last_refresh
	diff = mktime(datetime.now().timetuple()) - mktime(last_refresh.timetuple())
	
	if diff>refresh_int:
		os.system("clear")
		print "Scan on %s interface running since %s, %i minutes in total (last update @ %s)" % (iface_name, start_time.strftime("%H:%M:%S, %d/%m/%Y"), (mktime(datetime.now().timetuple()) - mktime(start_time.timetuple()))/60, datetime.now().strftime("%H:%M:%S, %d/%m/%Y"))
				
		file_name = filepath+"log_wifi-sniffer-clients-"+start_time.strftime("%H-%M-%S-%d-%m-%Y")+".csv"
		f = open(file_name, "w+")
		writer = csv.writer(f)
		writer.writerow(("SSID", "SSID MAC", "Client MAC", "RSSI", "Connected?", "First seen", "Last seen", "Debug"))
		
		for client in probing_APs.keys():
			for ssid in probing_APs[client]:
				writer.writerow((ssid, probing_APs[client][ssid]["ap_mac"], client, probing_APs[client][ssid]["rssi"], probing_APs[client][ssid]["connected"], probing_APs[client][ssid]["firstseen"], probing_APs[client][ssid]["lastseen"],probing_APs[client][ssid]["debug"]))
		f.close()
		print "\nClients log file saved to "+file_name
		
		file_name = filepath+"log_wifi-sniffer-APs-"+start_time.strftime("%H-%M-%S-%d-%m-%Y")+".csv"
		f = open(file_name, "w+")
		writer = csv.writer(f)
		writer.writerow(("SSID", "MAC", "Channel", "RSSI", "Security", "Hidden", "Rogue", "Received Deauth", "First seen", "Last seen", "Debug"))
		
		for ssid in nearby_APs.keys():
			for mac in nearby_APs[ssid]:
				received_deauth = str(deauth_receiving_APs[mac]) if mac in deauth_receiving_APs else "0"
				writer.writerow((ssid, mac, nearby_APs[ssid][mac]["channel"], nearby_APs[ssid][mac]["rssi"], nearby_APs[ssid][mac]["secured"], nearby_APs[ssid][mac]["hidden"], nearby_APs[ssid][mac]["rogue"], received_deauth, nearby_APs[ssid][mac]["firstseen"], nearby_APs[ssid][mac]["lastseen"], nearby_APs[ssid][mac]["debug"]))
		f.close()
		
		print "Nearby APs log file saved to "+file_name
		
		print "\n* Total nearby APs: %i" % (len(nearby_APs))
		print "* Total nearby clients: %i" % (len(probing_APs))
		if len(deauth_receiving_APs)>0:
			print "* APs receiving deauth packets: %s" % str(deauth_receiving_APs)
		last_refresh = datetime.now()

def channelHopper():
	global prev_channels

	while True:
		try:
			#switch channel, but exclude couple channels that we switched to last x times	
			wholerange = range(1,14)
			for c in prev_channels:
				if(c not in nearby_ap_channels):
					wholerange.remove(c)
			current_ch = random.choice(wholerange)
			if len(prev_channels)>3:
				prev_channels.pop(0)
			prev_channels.append(current_ch)
			proc = subprocess.Popen(['iw', 'dev', iface_name, 'set', 'channel', str(current_ch)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			time.sleep(0.5)
		except KeyboardInterrupt:
			break

def my_devices_debug(pkt):

	devices = {'00:00:00:00:00:00'}
	if pkt.addr1 in devices or pkt.addr2 in devices or pkt.addr3 in devices:
		print "\n-----\n got packet for/from device"
		print "packet details: " + str(pkt.type) + " : " + str(pkt.subtype) + "Dot11 layer: " + str(pkt.haslayer(Dot11))
		print pkt.addr1
		print pkt.addr2
		print pkt.addr3
		try:
			print pkt.info
		except Exception,e:
			print "no pkt.info"
		print datetime.now()
		print "-----" 

def PacketHandler(pkt):
	global last_refresh
	
	#enable for debugging
	#my_devices_debug(pkt)	
	#return
	
	if pkt.haslayer(Dot11) and (pkt.type==0 or pkt.type==1 or pkt.type==2):
		client_mac = ''
		ap_mac = ''
		ap_ssid = ''
		client_connected = '0'
		client_event = False
		ap_event = False
		mixed_addr_order = False
		
		if pkt.type==0 and pkt.subtype==0:
			ap_mac = pkt.addr1
			client_mac = pkt.addr2
			#print "This is Management frame: Association request (0:0)"
		elif pkt.type==0 and pkt.subtype==1:
			ap_mac = pkt.addr2
			client_mac = pkt.addr1
			#print "This is Management frame: Association request response (0:1)"
		elif pkt.type==0 and pkt.subtype==4:
			client_mac = pkt.addr2
			if pkt.info:
				ap_ssid = pkt.info
			client_event = True
			#print "This is Management frame: Probe request frame (0:4)"		
		elif pkt.type==0 and pkt.subtype==5:
			ap_mac = pkt.addr2
			client_mac = pkt.addr1
			ap_ssid = pkt.info
			ap_event = True
			#print "This is Management frame: Probe response frame (0:5)"				
		elif pkt.type==0 and pkt.subtype==8:
			ap_mac = pkt.addr2
			ap_ssid = pkt.info
			ap_event = True
			#print "This is Management frame: Beacon frame (0:8)"			
		#elif pkt.type==0 and pkt.subtype==10:
			#print "This is Management frame: Disassociation frame (0:10)"		
		elif pkt.type==0 and pkt.subtype==11:
			ap_mac = pkt.addr2
			client_mac = pkt.addr1
			mixed_addr_order = True
			#print "This is Management frame: Authentication frame (0:11)"
		elif pkt.type==0 and pkt.subtype==12:
			ap_mac = pkt.addr2
			deauth_count = 1
			if ap_mac in deauth_receiving_APs:
				deauth_count = deauth_receiving_APs[ap_mac]
				deauth_count = deauth_count + 1
			deauth_receiving_APs[ap_mac] = deauth_count
			#print "This is Management frame: Deauthentication frame (0:12)"
		elif pkt.type==0 and pkt.subtype==13:
			mixed_addr_order = True
			ap_mac = pkt.addr2
			client_mac = pkt.addr1
			#print "This is Management frame: Action frame (0:13)"
		elif pkt.type==1 and pkt.subtype==11:
			mixed_addr_order = True
			client_mac = pkt.addr1
			ap_mac = pkt.addr2
			#print "This is Control frame: RTS data (1:11)"
		elif pkt.type==2 and pkt.subtype==0:
			mixed_addr_order = True
			ap_mac = pkt.addr2
			client_mac = pkt.addr3
			#print "This is Data frame: Data frame (2:0)"
		elif pkt.type==2 and pkt.subtype==4:
			ap_mac = pkt.addr1
			client_mac = pkt.addr2
			client_connected = '1'
			#print "This is Data frame: Null data (2:4)"
		elif pkt.type==2 and pkt.subtype==8:
			mixed_addr_order = True
			client_connected = '1'
			client_mac = pkt.addr1
			ap_mac = pkt.addr2
			#print "This is Data frame: QoS data (2:8)"
		elif pkt.type==2 and pkt.subtype==12:
			client_connected = '1'
			client_mac = pkt.addr2
			ap_mac = pkt.addr1
			#print "This is Data frame: QoS Null data (2:12)"
		else:
			return

		if mixed_addr_order:
			real_client_mac = ''
			real_ap_mac = ''
			if ap_mac==client_mac:
				client_mac = '' #avoid self-broadcasts
			if len(ap_mac)>0 and ap_mac in nearby_MACs:
				real_client_mac = client_mac
				real_ap_mac = ap_mac
				client_event = True
			elif len(client_mac)>0 and client_mac in nearby_MACs:
				real_client_mac = ap_mac
				real_ap_mac = client_mac
			ap_mac = real_ap_mac
			client_mac = real_client_mac

		if len(client_mac)>0:
		#log all clients nearby - those probing (with or without SSID being seen) or connected
			ssids = {}
			ssid = '' #leave blank or populate if a)client is connected or b)client sent probe request
			if ap_mac in nearby_MACs and client_connected=='1':
				ssid = nearby_MACs[ap_mac]
			elif len(ap_ssid)>0 and client_event:
				ssid = ap_ssid
					
			if client_mac in probing_APs.keys():
				ssids = probing_APs[client_mac]

			if ssid not in ssids.keys():
				ssids[ssid]={}
				ssids[ssid]['firstseen'] = datetime.now()
				ssids[ssid]['rssi'] = ''
			
			ssids[ssid]['connected'] = client_connected
			ssids[ssid]['lastseen'] = datetime.now()
			ssids[ssid]['debug'] = str(pkt.type) + ':' + str(pkt.subtype)
			
			if client_event:
				try:
					ssids[ssid]['rssi'] = "-" + str(256-ord(pkt.notdecoded[-4:-3])) + "dBm"
				except Exception,e:
					if ssids[ssid]['rssi'] == '':
						ssids[ssid]['rssi'] = ''
			
			if client_connected=='1':
				ssids[ssid]['ap_mac'] = ap_mac
			else:
				ssids[ssid]['ap_mac'] = ''
			
			if '' in ssids.keys():
			#remove zero ssid once customer connects to something or gives probe responses with SSID names - zero ssid is either for hidden SSID (keeping those when customer is connected) or when client is probing
			#also update any SSID info in case MAC was logged before SSID name was known
				if ssids['']['connected']!='1' and len(ssids)>1:
					del ssids['']
				elif ssids['']['connected']=='1' and ssids['']['ap_mac'] in nearby_MACs:
					ssid_replace = ssids[''];
					ssid = nearby_MACs[ssid_replace['ap_mac']]
					ssids[ssid]=ssid_replace
					del ssids['']

			probing_APs[client_mac] = ssids
			
		elif len(ap_mac)>0 or len(ap_ssid)>0:
			mac_details = {}
			if ap_mac in nearby_MACs:
				ssid = nearby_MACs[ap_mac]
			else:
				ssid = ap_ssid
				
			if ssid in nearby_APs.keys():
				mac_details = nearby_APs[ssid]
				
			if ap_mac not in mac_details.keys():
				mac_details[ap_mac]={}
				mac_details[ap_mac]['firstseen'] = datetime.now()
				mac_details[ap_mac]['rssi'] = ''
					
			mac_details[ap_mac]['lastseen'] = datetime.now()
			mac_details[ap_mac]['debug'] = str(pkt.type) + ':' + str(pkt.subtype)
				
			#attempt to check for rogue AP and try to exract additional AP/client details
			if ssid in monitored_APs.keys() and ap_mac not in monitored_APs[ssid]:
				mac_details[ap_mac]['rogue'] = "1"
			else:
				mac_details[ap_mac]['rogue'] = "0"
					
			try:
				if ap_event:
					cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}""{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')
							
					if 'privacy' in cap:
						mac_details[ap_mac]['secured'] = "1"
					else:
						mac_details[ap_mac]['secured'] = "0"
							
					if ssid.startswith('\x00'):
						mac_details[ap_mac]['hidden'] = "1"
					else:
						mac_details[ap_mac]['hidden'] = "0"
								
					mac_details[ap_mac]['channel'] = str(ord(pkt[Dot11Elt:3].info))
					nearby_ap_channels.add(str(ord(pkt[Dot11Elt:3].info)))
					
					try:
						mac_details[ap_mac]['rssi'] = "-" + str(256-ord(pkt.notdecoded[-4:-3])) + "dBm"
					except Exception,e:
						if mac_details[ap_mac]['rssi'] == '':
							mac_details[ap_mac]['rssi'] = ''
					
					if '' in nearby_APs.keys():
					#remove zero ssid for MAC address if this MAC address was previously linked to zero ssid
						if ap_mac in nearby_APs['']:
							del nearby_APs[''][ap_mac]
				else:
					mac_details[ap_mac]['secured'] = ""
					mac_details[ap_mac]['hidden'] = ""
					mac_details[ap_mac]['channel'] = ""
			except Exception, e:
				mac_details[ap_mac]['secured'] = "-1"
				mac_details[ap_mac]['hidden'] = "-1"
				mac_details[ap_mac]['channel'] = "-1"
			nearby_APs[ssid] = mac_details
					
			#add MAC and AP to separate array that allows to match currently connected clients to AP by looking up AP mac address
			if ap_mac not in nearby_MACs:
				nearby_MACs[ap_mac] = ssid
		
	do_logging = Process(target = outputData(probing_APs, nearby_APs))
	do_logging.start()


def stop_processes(signal, frame):
	channel_hop.terminate()
	channel_hop.join()
	do_logging.terminate()
	do_logging.join()


os.system("clear")
print "\n----\n"
print "Wi-Fi sniffer is a tool that allows you to see clients currently trying to connect to access points (APs) by sending probe requests."
print "You can also see all APs in the proximity. Additionally, you can try to identify rogue APs as they appear (see monitored_APs) or identify APs that are targeted using deauth attacks (see deauth_receiving_APs)."
print "N.B. - the script will hop wifi channels constantly to discover more APs nearby."
print "\n----\n"
print "To start with, let's set some parameters \n"

i_iface_name=raw_input("Interface to use (default: wlan1):")
iface_name = "wlan1" if i_iface_name=="" else i_iface_name
i_refresh_interval=raw_input("Refresh interval in seconds (default: 30):")
refresh_int = 30 if i_refresh_interval=="" else int(i_refresh_interval)

	
start_time = datetime.now()
last_refresh = datetime.now()

print "\n----"
print "Please wait %i seconds for initial results..." % (refresh_int)
	
do_logging = Process(target = outputData(probing_APs, nearby_APs))
do_logging.start()
channel_hop = Process(target = channelHopper)
channel_hop.start()
signal.signal(signal.SIGINT, stop_processes)
sniff(iface=iface_name, lfilter=lambda x: (x.haslayer(Dot11)), prn=PacketHandler, store=False)
