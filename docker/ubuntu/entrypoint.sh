#!/bin/bash

# Create the data directory if it doesn't exist
mkdir -p /data

# Run Wireshark for 60 seconds and save the output to a file in the mounted volume
tshark -i eth0 -a duration:20 -w /data/capture.pcap

# Make the output file readable by all users
chmod a+r /data/capture.pcap

# Run a loop to keep the container running
while true; do sleep 2; done

exit 0