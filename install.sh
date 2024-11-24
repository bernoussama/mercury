#!/bin/bash

set -e
mkdir -p ~/mercury/zones
cd ~/mercury

# wget https://raw.githubusercontent.com/bernoussama/mercury/main/zones/example.yml -O zones/example.yml;
wget https://raw.githubusercontent.com/bernoussama/mercury/main/compose.yaml -O compose.yaml

read -p "port: " PORT
export PORT

read -p "run as root? (y/n) " yn

if [ "$yn" = "y" ]; then
  echo "running as root"
  sudo docker compose up -d
  echo "done"
fi
