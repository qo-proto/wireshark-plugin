#!/bin/bash

docker build . -t wireshark-plugin
docker run --rm -v $(pwd)/libs:/output wireshark-plugin

mkdir -p ~/.local/lib/wireshark/plugins
cp libs/* ~/.local/lib/wireshark/plugins/
