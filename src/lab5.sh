#!/bin/bash
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python -m venv venv
fi

echo "Activating virtual environment..."
if [ -f "venv/Scripts/activate" ]; then
    source venv/Scripts/activate
else
    source venv/bin/activate
fi

echo "Upgrading pip and installing required packages..."
# pip install --upgrade pip
pip install pyshark requests

echo "Running lab5.py..."
python lab5.py

echo "Deactivating virtual environment..."
deactivate
