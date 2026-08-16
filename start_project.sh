#!/bin/bash
cd "$(dirname "$0")"

echo "Starting Docker Desktop..."
open -a Docker
echo "Waiting for Docker to be ready (this can take ~30-60s)..."
until docker info > /dev/null 2>&1; do
  sleep 2
done

echo "Starting containers..."
docker compose up -d
echo "Waiting for Elasticsearch to be healthy..."
sleep 15

echo "Starting background processes..."
nohup python3 -u generators/auth_sim.py > logs/auth_sim_output.log 2>&1 &
disown
echo $! > logs/auth_sim.pid

nohup python3 -u pipeline/watcher.py > logs/watcher_output.log 2>&1 &
disown
echo $! > logs/watcher.pid

echo "Done. Generator PID: $(cat logs/auth_sim.pid), Watcher PID: $(cat logs/watcher.pid)"