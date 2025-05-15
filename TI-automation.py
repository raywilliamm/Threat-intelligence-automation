import asyncio
from pycti import OpenCTIApiClient
import re
import vt
from PfsenseFauxapi.PfsenseFauxapi import PfsenseFauxapi
import requests
from requests.auth import HTTPBasicAuth

# OpenCTI and VirusTotal configuration
api_url = "{OPENCTI_URL}"
api_token = '{OPENCTI_API}'

# VirusTotal configuration
VT_API_KEY = '9382a4e7d8af389bf0e304b2233dbd5b060bcbfc89b4891c7ccd6fd199418ffc'

# FauxAPI configuration
PFSENSE_HOST = '{HOST_IP}'
PFSENSE_APIKEY = '{APIKEY}'
PFSENSE_SECRET = '{SECRET_KEY}'
ALIAS_NAME = 'Malicious_IPs'  # The alias to which you want to add the IP addresses

# Initialize clients
opencti_api_client = OpenCTIApiClient(api_url, api_token)
PfsenseFauxapi = PfsenseFauxapi(PFSENSE_HOST, PFSENSE_APIKEY, PFSENSE_SECRET)

# Function to add an IP address to a pfSense alias
def add_ip_to_alias(ip_address):
    # Fetch the current full configuration
    full_config = PfsenseFauxapi.config_get()

    # Key path
    aliases = full_config['aliases']['alias']

    # Check if the 'Malicious_IPs' alias exists
    malicious_ips_alias = next((item for item in aliases if item["name"] == "Malicious_IPs"), None)

    if malicious_ips_alias:
        # Append the new IP address to the alias with a space as the separator
        existing_addresses = malicious_ips_alias['address'].split()  # Split current addresses into a list
        if ip_address not in existing_addresses:
            existing_addresses.append(ip_address)  # Add the new IP address
            malicious_ips_alias['address'] = ' '.join(existing_addresses)  # Join the list back into a string with spaces
    else:
        # If the alias doesn't exist, create it
        aliases.append({
            "name": ALIAS_NAME,
            "type": "host",
            "address": ip_address,
            "descr": "List of malicious IP addresses"
        })

    # Apply the new configuration
    PfsenseFauxapi.config_set(full_config)
    # Reload the firewall filter to apply changes
    PfsenseFauxapi.send_event("filter reload")

    # Print the IP has been successfully added
    print(f"Malicious IP {ip_address} has been added to the firewall.")

# Function to get IP addresses from OpenCTI
def get_ip_addresses():
    indicators = opencti_api_client.indicator.list()
    ip_addresses = []
    ipv4_pattern = re.compile(r"\[ipv4-addr:value = '([^']+)'\]")
    for indicator in indicators:
        match = ipv4_pattern.search(indicator['pattern'])
        if match:
            ip_addresses.append(match.group(1))
    return ip_addresses

# Async function to check an IP address with VirusTotal
async def check_ip_with_virustotal(client, ip_address):
    try:
        ip_report = await client.get_object_async(f"/ip_addresses/{ip_address}")
        malicious_count = ip_report.get('last_analysis_stats', {}).get('malicious', 0)
        if malicious_count > 0:
            add_ip_to_alias(ip_address)
        return ip_address, malicious_count > 0, None
    except vt.error.APIError as e:
        print(f"Error checking IP {ip_address}: {e}")
        return ip_address, False, e

# Main async function
async def main():
    ip_addresses = get_ip_addresses()[:10]  # Limit the number of IP addresses to check
    async with vt.Client(VT_API_KEY) as client:
        tasks = [asyncio.create_task(check_ip_with_virustotal(client, ip_address)) for ip_address in ip_addresses]
        await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main())
