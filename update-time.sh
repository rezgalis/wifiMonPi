#!/bin/sh
#set correct time based on user inputs
echo "Hello! My current date and time is $(date +'%d/%m/%Y @ %H:%M:%S')"
echo "If it is correct, you can exit the script. If not, please provide the updated values."
echo "\n\n"
echo "Day: "
read input_day
echo "Month (with leading zero if necessary): "
read input_month
echo "Year: "
read input_year
echo "Hour (24h format): "
read input_hour
echo "Minute: "
read input_minute
echo "Second (add 2 to compensate delay while setting): "
read input_second
sudo date  +%Y%m%d -s "$input_year$input_month$input_day" 
sudo date +%T -s "$input_hour:$input_minute:$input_second" 
echo "Date and time updated. Now my current date and time is $(date +'%d/%m/%Y @ %H:%M:%S')"

