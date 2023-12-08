#!/bin/bash
# must be root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi
if [ -f "installed.txt" ]; then
    python wireless_scanner.py
    exit 1
fi
# install apt packages if not exists libbluetooth-dev librtlsdr-dev
if ! dpkg -s libbluetooth-dev librtlsdr-dev >/dev/null 2>&1; then
    apt update
    apt install -y libbluetooth-dev librtlsdr-dev
fi

# Create Python virtual environment in the current directory if needed
if [ ! -d "wireless-scanner-venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv wireless-scanner-venv
fi

# Activate virtual environment if needed
echo "Activating Python virtual environment..."
if [ ! -f "wireless-scanner-venv/bin/activate" ]; then
    echo "Python virtual environment not found"
    unlink installed.txt || true
    exit 1
fi
source wireless-scanner-venv/bin/activate

# Install required packages if needed
echo "Installing required Python packages..."
pip install -r requirements.txt
touch installed.txt
# Run the script
python wireless_scanner.py
