mkdir -p ~/mercury/zones
cd ~/mercury
wget https://raw.githubusercontent.com/bernoussama/mercury/main/compose.yaml -O compose.yaml
read -p "run as root? (y/n) " yn
if [ "$yn" = "y" ]; then
  echo "running as root"
  sudo docker compose up -d
  echo "done"
fi
exit 0
