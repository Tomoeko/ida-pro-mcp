#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Configuration path for Antigravity IDE
CONFIG_PATH="$HOME/.gemini/config/mcp_config.json"

echo "=========================================================="
echo "Installing ida-pro-mcp to Antigravity IDE"
echo "=========================================================="

# 1. Check if the configuration already exists in mcp_config.json
if [ -f "$CONFIG_PATH" ]; then
    if python3 -c "
import json, sys
try:
    with open('$CONFIG_PATH', 'r') as f:
        data = json.load(f)
    if 'mcpServers' in data and 'ida-pro-mcp' in data['mcpServers']:
        sys.exit(0)
except Exception:
    pass
sys.exit(1)
" ; then
        echo "Check: ida-pro-mcp is already configured in Antigravity IDE."
        echo "Config path: $CONFIG_PATH"
        echo "No actions needed. Exiting."
        exit 0
    fi
fi

echo "Not found in $CONFIG_PATH. Proceeding with installation..."

# 2. Check Python version
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "Detected Python version: $PYTHON_VERSION"

# Ensure Python version is 3.11 or higher
if python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then
    echo "Python version is compatible."
else
    echo "Error: Python 3.11 or higher is required. Found: $PYTHON_VERSION"
    exit 1
fi

# 3. Install/update packages in editable mode to ensure all dependencies are resolved
echo "Installing/updating python package dependencies..."
if command -v uv &> /dev/null; then
    echo "Using uv to install package in editable mode..."
    uv pip install -e .
else
    echo "Using pip to install package in editable mode..."
    if ! python3 -m pip install -e . ; then
        echo "Pip install failed. Retrying with --break-system-packages for externally managed environments..."
        python3 -m pip install -e . --break-system-packages
    fi
fi

# 4. Configure Antigravity IDE and link IDA Pro plugin
echo "Running the installer to configure Antigravity IDE and link the IDA Pro plugin..."
python3 -m ida_pro_mcp.server --install antigravity --scope global --transport stdio

echo "=========================================================="
echo "Installation complete!"
echo "Please restart IDA Pro and Antigravity IDE to apply the changes."
echo "=========================================================="
