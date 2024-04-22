# ❄️ 🚜 ColdFarm

ColdFarm is a side project derived from Cold Clarity, designed to streamline the process of pulling endpoint data from Cisco Workload and ACI, and integrating it into Cisco ISE's database. This program aims to enhance network visibility and security posture by ensuring that all endpoints are accurately represented within the ISE environment.

## Features

- 📡 Pulls endpoint data from CSW and ACI.
- 🔄 Integrates endpoint data into Cisco ISE's database.
- 👀 Enhances network visibility and security posture.

## Requirements

- 🐍 Python 3.x
- 💻 Cisco Workload (CSW)
- 📟 Cisco Application Centric Infrastructure (ACI)
- 🔒 Cisco ISE

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/OObasuyi/ColdFarm.git
    ```

2. Install the required dependencies:

    ```bash
    pip install -r requirements.txt
    ```

## Configuration WIP

Before running the program, ensure that you have properly configured the following:

1. 🛠 Cisco Workload (ACI) credentials.
2. 🔑 Cisco ISE credentials.
3. 🚪 Necessary permissions to access endpoint data from Cisco Workload and ACI.
4. 🌐 Proper network connectivity between the ColdFarm and Data Systems.

## Usage (WIP)
### Source Code
1. Navigate to the ColdFarm directory:

    ```bash
    cd ColdFarm
    ```

2. Run the ColdFarm program:
   
    ```bash
    python term_access.py --config_file config.yaml
    ```
   **FOR TESTING**
    ```bash
    python term_access.py --config_file config.yaml --test_count 500 --test_seed 340 # seed for non random macs useful for testing updates
    ```

3. 🪄 Magic
### Containers

1. install the container tar from the [releases](https://github.com/OObasuyi/ColdFarm/releases) 
   ```bash
   podman load -i coldfarm.tar 
   ```

2. run the container 
   ```bash
   podman run -it -v /PATH/TO/<CONFIG_NAME>.yaml:/ColdFarm/configs/config.yaml:Z coldfarm
   ```

3. 🪄 Magic AGAIN