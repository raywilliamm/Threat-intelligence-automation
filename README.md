# TI-automation

This repository contains "TI-automation", a Python script developed by Ray that automates the process of retrieving malicious IP addresses from OpenCTI, verifying them with VirusTotal, and dynamically updating a pfSense firewall to block these IPs.

## Features

- Retrieves malicious IP from OpenCTI.
- Checks the credibility of IP addresses with VirusTotal.
- Dynamically updates pfSense firewall aliases for IP blocking via FauxAPI.

## Prerequisites

Ensure you have access to OpenCTI, a VirusTotal API key, and a pfSense firewall with the FauxAPI package installed.

## Installation

Clone the repository using:

```bash
git clone https://github.com/raywilliamm/Threat-Intelligence-automation.git
```
Then, install the required Python libraries:
```
pip install -r requirements.txt
```

## Usage
After cloning the repository and installing dependencies, configure your credentials in the config.py file. Run the script with the following command:

```bash
python TI-automation.py
```

## License



## Contact
Ray William 
Project Link: https://github.com/raywilliamm/Threat-intelligence-automation
