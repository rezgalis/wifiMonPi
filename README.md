# wifiMonPi

Python script (and some supporting shell scripts) is intended for monitoring nearby wi-fi networks and devices. Script monitors for beacon frames and beacon responses from wifi access points, and also monitors nearby devices sending probe requests (that's what mobile phones usually do and by doing this disclose all possible access points it would try to connect to) and nearby connected devices.
The script was built to work on Raspberry Pi model 3 ver B which has built-in wifi (used for local AP - for accessing logs, visualisation webpage and for management through ssh) and an extra wifi adapter which is then set in monitor mode to sniff wi-fi frames.
Log files are saved to /var/www directory and can be displayed nicely using lighttpd and jQuery-CSV (https://github.com/evanplaice/jquery-csv).
You can find out more about wifi management frames e.g. here: http://www.wi-fiplanet.com/tutorials/article.php/1447501/Understanding-80211-Frame-Types.htm


## Full setup instructions
