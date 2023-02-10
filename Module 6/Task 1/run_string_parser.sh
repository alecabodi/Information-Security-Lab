#Runs StringParser independently; make sure, that this is the only instance running!
echo "Starting StringParser"
rm /home/isl/t1/string_parser.log
python3 /home/isl/t1/sp_server.py  &> /home/isl/t1/string_parser.log &
echo "StringParser Logs"
echo "--------------------------------------------"
until [ -f /home/isl/t1/string_parser.log ]
do
     sleep 0.5
done
sleep 2
python3 /home/isl/t1/test_string_parser.py
echo "--------------------------------------------"
