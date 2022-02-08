#! /bin/bash

choice=$1
data=$2

if [ "$choice" == "decode" ]; then
    echo "Decoding ==> $data"
    echo "$data" | xxd -r -ps

elif [ "$choice" == "encode" ]; then
    echo "Encoding ==> $data"
    echo "$data" | xxd -ps

else
    echo "./convert.sh encode/decode <HEX data/RAW data>"
fi
