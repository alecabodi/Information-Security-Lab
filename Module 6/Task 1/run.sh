#!/bin/bash
pkill -9 node
kill $(pgrep -f 'sp_server.py')
rm -f /home/isl/t1/manager.log
rm -f /home/isl/t1/string_parser.log
rm -f /home/isl/t1/peripheral.log
sleep 2
echo "Starting Manager"
node --no-warnings /home/isl/t1/manager &> /home/isl/t1/manager.log &
echo "Manager Logs"
echo "--------------------------------------------"
sleep 2
cat /home/isl/t1/manager.log
echo "--------------------------------------------"
echo ""

sleep 2
echo "Starting Peripheral"
node --no-warnings /home/isl/t1/peripheral &> /home/isl/t1/peripheral.log &
echo "Peripheral Logs"
echo "--------------------------------------------"
sleep 2
cat /home/isl/t1/peripheral.log
echo "--------------------------------------------"
echo ""

sleep 2
echo "Starting StringParser"
python3 -u /home/isl/t1/sp_server.py  &> /home/isl/t1/string_parser.log &
echo "StringParser Logs"
sleep 5

echo "--------------------------------------------"
sleep 2
cat /home/isl/t1/string_parser.log
echo "--------------------------------------------"

python3 /home/isl/t1/test_string_parser.py