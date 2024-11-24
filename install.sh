mkdir -p ~/mercury
cd ~/mercury
read -p "run as root? (y/n) " yn
if [ "$yn" = "y" ]; then
  echo "running as root"
  sudo docker compose up -d
  echo "done"
fi
exit 0
