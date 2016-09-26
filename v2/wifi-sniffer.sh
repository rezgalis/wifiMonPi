#!/bin/sh
#start monitor mode on wlan1 and open python script to configure & start sniffing

sudo ifconfig wlan1 down
sudo iwconfig wlan1 mode monitor
sudo ifconfig wlan1 up

sudo rfkill unblock wifi

cd /home/pi/scripts/wifi-sniffer/
sudo python wifi-sniffer.py
