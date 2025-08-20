# Decentralised Secure File Storage - UI Application

This is the user interface for the Decentralised Secure File Storage system. It is a desktop application built with Python and Tkinter that provides a complete, user-friendly interface for interacting with the `FileRegistry` smart contract on the Polygon test network.

## Prerequisites

Before you begin, ensure you have the following installed on your system:

1.  **Python 3.10+:** This application is built on Python 3.10. You can download it from [python.org](https://www.python.org/downloads/). Make sure to check the box that says **"Add Python to PATH"** during installation.
2.  **Git:** You will need Git to clone the repository. You can download it from [git-scm.com](https://git-scm.com/downloads).

## 🚀 Quick Start: Running the Application

Follow these steps exactly to set up and run the UI application.

### Step 1: Clone the Repository

### Step 2: Set Up the Environment

All project dependencies are managed in a virtual environment to avoid conflicts with your system's Python packages.

#### Create a Python virtual environment in a folder named .venv
```
python -m venv .venv

# Activate the virtual environment
# On Windows:
.\.venv\Scripts\Activate
# On macOS/Linux:
# source .venv/bin/activate
```
Open the .env file in a text editor and fill in the following values:
```
POLYGON_AMOY_RPC_URL="https"

# The address of the deployed FileRegistry smart contract
CONTRACT_ADDRESS="0x..."

# The JWT token from your Pinata account for IPFS pinning
PINATA_JWT="YOUR_PINATA_JWT_HERE"

```  

   Install Dependencies

With your virtual environment active, run the following command to install the Python client package and all its required libraries. This command reads the setup.py and requirements.txt from the python-client directory.
    
#### Make sure you are in the root directory of the project
```
pip install -e ./python-client_v2
pip install -r requirements.txt
```
Step 5: Run the Application

You are now ready to launch the UI. Navigate to the ui_app directory and run the main.py script.
```
cd ui_app
python main.py
```

  