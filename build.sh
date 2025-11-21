#!/bin/bash

docker build -f Dockerfile.linux -t wireshark-plugin-linux .
docker run --rm -v $(pwd)/libs:/output wireshark-plugin-linux

docker build -f Dockerfile.windows -t wireshark-plugin-windows .
docker run --rm -v $(pwd)/libs:/output wireshark-plugin-windows