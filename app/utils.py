# utils.py

import subprocess
import pandas as pd
import nmap
from datetime import datetime
from scapy.all import sniff
import os
import base64
import time
import hashlib
import requests
import json
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("VIRUS_TOTAL_API_KEY")

def getNetworkDevices(runtime=10):
    try:
        process = subprocess.Popen(
            ["bettercap", "-no-colors", "-iface", "en0", "-eval",
             "net.probe on; sleep 5; net.show; net.probe off; quit"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )

        stdout, stderr = process.communicate(timeout=15)

        devices = []
        in_table = False
        
        for line in stdout.splitlines():
            # Skip all lines starting with [ until we find the table
            if not in_table:
                if line.startswith('┌─'):
                    in_table = True
                    continue  # Skip the top border line
                elif line.startswith('['):
                    continue  # Skip other log lines
                else:
                    continue  # Skip everything before table

            # Process table lines
            if in_table:
                # Stop when we hit empty line after table
                if not line.strip():
                    break
                
                # Skip middle border lines (├─...┤) and header line
                if any(c in line for c in ['├─', '┤', 'IP Address']):
                    continue
                
                # Split and clean table row
                parts = [p.strip() for p in line.split('│') if p.strip()]

                if len(parts) >= 4:
                    devices.append({
                        "IP Address": parts[0],
                        "MAC Address": parts[1],
                        "Host Name": parts[2],
                        "Manufacterer": parts[3]
                    })

        # Filter devices: only include entries with a host name ending with ".local"
        filtered_devices = [device for device in devices 
                            if device.get("Host Name", "").endswith(".local")]

        print(filtered_devices)
        return filtered_devices

    except subprocess.TimeoutExpired:
        process.kill()
        print("Process timed out")
        return []
    except Exception as e:
        print(f"Error: {str(e)}")
        return []

def capture_packets():
    """
    Capture network packets and return a DataFrame containing their details.
    """
    packets_data = []

    def packet_callback(packet):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        if packet.haslayer('IP'):
            ip_src = packet['IP'].src
            ip_dst = packet['IP'].dst
            protocol = packet.proto
            src_port = dst_port = None

            if packet.haslayer('TCP'):
                src_port = packet['TCP'].sport
                dst_port = packet['TCP'].dport

            elif packet.haslayer('UDP'):
                src_port = packet['UDP'].sport
                dst_port = packet['UDP'].dport

            packet_summary = packet.summary()

            packets_data.append({
                'Timestamp': timestamp,
                'Source IP': ip_src,
                'Destination IP': ip_dst,
                'Protocol': protocol,
                'Source Port': src_port,
                'Destination Port': dst_port,
                'Packet Summary': packet_summary
            })

    sniff(prn=packet_callback, store=0, timeout=5)  # Sniff packets for 10 seconds (adjust as needed)

    return pd.DataFrame(packets_data)
import nmap
import pandas as pd

def portscanner():
    nm = nmap.PortScanner()
    nm.scan('127.0.0.1', '0-1023')

    port_data = []
    port_list = nm['127.0.0.1']['tcp'].keys()
    for port in port_list:
        if nm['127.0.0.1'].has_tcp(port):
            proto = 'tcp'
            port_data.append({
                'port': port,
                'tcpProtocol': proto,
                'portInfo': nm['127.0.0.1'][proto][port],
                'portState': nm['127.0.0.1'][proto][port]['state'],
            })
    df = pd.DataFrame(port_data)
    print(df)
    return df

""""""
report_time = ' '

def urlReport(url):
    """
    Submits a URL to VirusTotal, parses the returned JSON,
    and returns a dictionary with exactly 9 elements:
      - url
      - community_score
      - last_analysis_date (as a datetime object)
      - last_analysis_stats (as a dictionary)
      - redirection_chain (as provided by the API, or None)
      - reputation (as an integer, or None)
      - times_submitted (as an integer, or None)
      - tld (as a string, or None)
      - virustotal_report (a URL string to the VT report)
    """
    # Log progress for debugging
    print("Processing URL report...")

    # Set the target URL from the input
    target_url = url

    # Create VirusTotal URL identifier:
    # Encode the target URL to base64 and remove padding
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")

    # Construct the VirusTotal API URL using the identifier
    vt_request_url = "https://www.virustotal.com/api/v3/urls/" + url_id

    # Prepare headers (API key is stored in .env)
    headers = {
        "Accept": "application/json",
        "x-apikey": API_KEY
    }

    # Make the GET request to VirusTotal
    response = requests.request("GET", vt_request_url, headers=headers)
    decodedResponse = json.loads(response.text)

    # Record the current timestamp to generate the report time
    timeStamp = time.time()
    global report_time
    report_time = time.strftime('%c', time.localtime(timeStamp))

    # Retrieve the epoch from the last analysis date contained in the VT data
    epoch_time = decodedResponse["data"]["attributes"]["last_analysis_date"]
    # Convert the epoch timestamp to a datetime object
    last_analysis_date = datetime.fromtimestamp(epoch_time)

    # Create the VT report URL link.
    # Build a link by hashing a constructed URL string.
    UrlId_unEncrypted = "http://" + target_url + "/"
    def encrypt_string(hash_string):
        return hashlib.sha256(hash_string.encode()).hexdigest()
    sha_signature = encrypt_string(UrlId_unEncrypted)
    vt_urlReportLink = "https://www.virustotal.com/gui/url/" + sha_signature

    # Grab the "attributes" dictionary from the response.
    attributes = decodedResponse["data"]["attributes"].copy()

    # Compute community score info based on last_analysis_stats.
    last_analysis_stats = attributes["last_analysis_stats"]  # This remains in our output.
    community_score_value = last_analysis_stats["malicious"]
    total_vt_reviewers = (last_analysis_stats["harmless"] +
                          last_analysis_stats["malicious"] +
                          last_analysis_stats["suspicious"] +
                          last_analysis_stats["undetected"] +
                          last_analysis_stats["timeout"])
    community_score_info = f"{community_score_value}/{total_vt_reviewers}  :  security vendors flagged this as malicious"

    # Now, we need to remove keys that we don't want in our final output.
    # However, we need to preserve the ones that our model requires.
    # The required fields are: 
    #   last_analysis_stats, redirection_chain, reputation, times_submitted, tld.
    # We'll extract these from the attributes (if present).
    redirection_chain = attributes.get("redirection_chain", None)
    reputation = attributes.get("reputation", None)
    times_submitted = attributes.get("times_submitted", None)
    tld = attributes.get("tld", None)
    
    # Build the final dictionary with exactly 9 keys:
    result_dict = {
        "url": target_url,
        "community_score": community_score_info,
        "last_analysis_date": last_analysis_date,
        "last_analysis_stats": last_analysis_stats,
        "redirection_chain": redirection_chain,
        "reputation": reputation,
        "times_submitted": times_submitted,
        "tld": tld,
        "virustotal_report": vt_urlReportLink
    }

    print("Report processing complete.")
    return result_dict