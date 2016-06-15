# wifiMonPi

Python script (and some supporting shell scripts) is intended for monitoring nearby wi-fi networks and devices. Script monitors for beacon frames and beacon responses from wifi access points, and also monitors nearby devices sending probe requests (that's what mobile phones usually do and by doing this disclose all possible access points it would try to connect to) and nearby connected devices.
The script was built to work on Raspberry Pi model 3 ver B which has built-in wifi (used for local AP - for accessing logs, visualisation webpage and for management through ssh) and an extra wifi adapter which is then set in monitor mode to sniff wi-fi frames.
Log files are saved to /var/www directory and can be displayed nicely using lighttpd and jQuery-CSV (https://github.com/evanplaice/jquery-csv).
You can find out more about wifi management frames e.g. here: http://www.wi-fiplanet.com/tutorials/article.php/1447501/Understanding-80211-Frame-Types.htm


## Full setup instructions
1. Format SD card, copy NOOBS to it (https://www.raspberrypi.org/downloads/noobs/)
2. Plug in SD card into RasPi, install Raspbian.
3. Change timezone, locale, admin password, enable ssh access, configure to boot to console with password (all through "sudo raspi-config")
4. Connect to internet and perform update 
    sudo apt-get update
    sudo apt-get dist-upgrade
5. Install required software:
    sudo apt-get install python-pip dnsmasq lighttpd hostapd tcpdump rfkill aircrack-ng
    sudo pip install scapy
6. Configure wlan0 to be the local wifi access point
    sudo mv /etc/dnsmasq.conf /etc/dnsmasq.conf.original
    sudo nano /etc/dnsmasq.conf
      interface=wlan0
      dhcp-range=192.168.8.100,192.168.8.120,12h
    sudo nano /etc/hostapd/hostapd.conf
      interface=wlan0
      driver=nl80211
      ssid=<ANY SSID NAME>
      hw_mode=g
      channel=6
      auth_algs=1
      wpa=2
      wpa_key_mgmt=WPA-PSK
      wpa_passphrase=<ANY PASSWORD 8chars at least>
      rsn_pairwise=CCMP
    sudo nano /etc/network/interfaces
      auto wlan0
      iface wlan0 inet static
      hostapd /etc/hostapd/hostapd.conf
      address 192.168.8.1
      netmask 255.255.255.0
      allow-hotplug wlan1
      #iface wlan1 inet manual
      #    wpa-conf /etc/wpa_supplicant/wpa_supplicant.conf
    sudo reboot   <-after this you should see your wifi access point and should be able to connect to it. Entering 192.168.1.1 in browser should open sample webpage for lighttpd
7. (optional) Enable directory listing in webserver
    sudo nano /etc/lighttpd/lighttpd.conf
      server.dir-listing = "enable"
8. Copy contents of "html" folder from this repository to lighttpd webserver folder
    sudo mv index.html /var/www/html
    sudo mv wifilog /var/www/html
    sudo chmod u=rw,o=r index.hhtml
    sudo chmod 0755 wifilog/ -R
9. Copy contents of "scripts" folder from this repository to folder "wifi-sniffer" in your home folder and chmod those scripts
    sudo chmod +x /home/pi/wifi-sniffer/update-time.sh
    sudo chmod +x /home/pi/wifi-sniffer/wifi-sniffer.sh


## Getting results and reviewing them

Optionally you can adjust time on your RasPi by running /home/pi/update-time.sh - follow instructions on screen

To start wifi-sniffer automatically (and in background), just run /home/pi/wifi-sniffer.sh 
Results will be output to /var/www/html/wifilog/data directory (you can ajdust line 18 in wifi-sniffer.py to change this)

Alternatively, just run sudo python wifi-sniffer.py and follow instructions. Please note you might have to perform actions to put interface in monitor mode and unblock wifi before this works nicely.

To monitor for rogue APs (someone pretending to be your wifi network), change line 17 in wifi-sniffer.py accordingly.

To view results, connect to your wifi access point (set up on step 6 before) and navigate to 192.168.1.1. First, download the file you want to examine and then open any of the CSV parser links and enjoy.
