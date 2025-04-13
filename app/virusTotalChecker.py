import argparse
import time
import base64
import hashlib
import os
import requests
import json
import pandas as pd   # (No longer used for building the output)
from dotenv import load_dotenv
from datetime import datetime

# //////////////////////////////////////////////
#
# Python Automated VT API v3 IP address and URL analysis 2.0
# by Brett Fullam
#
# Accepts single entries for IP address or URL
# Performs bulk IP address analysis
# Performs bulk URL Analysis
#
# Outputs HTML report with hypertext links per entry
# to VirusTotal's web-based GUI for a full report
#
# //////////////////////////////////////////////

# load_dotenv will look for a .env file and if it finds one it will load the environment variables from it
load_dotenv()

"""
/////  IMPORTANT  /////
ADD .env to gitignore to keep it from being sent to github
and exposing your API key in the repository
"""

# retrieve API key from .env file and store in a variable
API_KEY = os.getenv("VIRUS_TOTAL_API_KEY")


# ////////////////////////////////// START Initiate the parser

parser = argparse.ArgumentParser(description="Python Automated VT API v3 IP address and URL analysis 2.0 by Brett Fullam")
parser.add_argument("-s", "--single-entry", help="ip or url for analysis")
parser.add_argument("-u", "--url-list", help="bulk url analysis")
parser.add_argument("-V", "--version", help="show program version", action="store_true")

# ////////////////////////////////// END Initiate the parser

# Initialize global variable for report time (if needed elsewhere)
report_time = ' '


# ////////////////////////////////// START URL REPORT REQUEST

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

# ////////////////////////////////// END URL REPORT REQUEST
