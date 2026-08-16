#!/bin/bash
echo "Stopping background processes..."
pkill -f "generators/auth_sim.py"
pkill -f "pipeline/watcher.py"

echo "Stopping Docker Desktop..."
pkill -9 -f "com.docker" 2>/dev/null
pkill -9 -f "Docker.app" 2>/dev/null

echo "Done. (com.docker.vmnetd may still show in ps - that's a lightweight root-owned system helper, harmless.)"