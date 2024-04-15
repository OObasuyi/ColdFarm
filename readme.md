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

## Usage WIP

1. Navigate to the ColdFarm directory:

    ```bash
    cd ColdFarm
    ```

2. Run the ColdFarm program:

    ```bash
    python term_access.py --config_file config.yaml
    ```

3. 🪄 Magic

## Contributing

Contributions are welcome! If you have any suggestions, feature requests, or bug reports, please [open an issue](https://github.com/OObasuyi/ColdFarm/issues) or [submit a pull request](https://github.com/OObasuyi/ColdFarm/pulls).

