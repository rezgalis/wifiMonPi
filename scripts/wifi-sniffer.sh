#!/bin/sh
#auto start monitor mode on wlan1 and ensure mon0 is active and wifi is unblocked, autostart wifi-sniffer python with params set

sudo ifconfig wlan1 down
sudo iwconfig wlan1 mode monitor
sudo ifconfig wlan1 up

FOUND="grep 'mon0' /proc/net/dev"
if [ -n "$FOUND" ]; then
sudo airmon-ng stop mon0
fi

sudo rfkill unblock wifi
sudo airmon-ng start wlan1
cd /home/pi
#sudo airodump-ng mon0 -w airodump.log &
sudo python wifi-sniffer.py --startup &
