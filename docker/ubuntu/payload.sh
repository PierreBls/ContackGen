#!/bin/bash

# Set the default values for the arguments
DURATION=180
OUTPUT=/data/capture.pcap

# Arguments manager
while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--duration)
            DURATION="$2"
            shift
            shift
            ;;
        -o|--output)
            OUTPUT="$2"
            shift
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  -d, --duration <duration>  Duration of the capture (default: 180 seconds)"
            echo "  -o, --output <output>      Output file (default: /data/capture.pcap))"
            echo "  -h, --help                 Show this help message"
            exit 0
            ;;
        *)
            echo "Invalid option: $1"
            echo "See --help for more information"
            exit 1
            ;;
    esac
done

# Show the arguments
echo "Entrypoint arguments:"
echo "  Duration:   $DURATION"
echo "  Output:     $OUTPUT"
echo ""

# Create the output directory if it doesn't exist
echo "Creating output directory: $(dirname $OUTPUT)"
mkdir -p $(dirname $OUTPUT)

# Run Wireshark for 60 seconds and save the output to a file in the mounted volume
tshark -i eth0 -a duration:${DURATION} -w ${OUTPUT}

# Make the output file readable by all users
chmod a+r /data/capture.pcap

exit 0