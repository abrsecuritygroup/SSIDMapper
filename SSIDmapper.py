#!/usr/bin/python

import http.server
import socketserver
import json
import pathlib
import sqlite3
import time
import subprocess
import requests
from requests.auth import HTTPBasicAuth
from mimetypes import MimeTypes
import re

"""THIS SCRIPT MUST BE RAN AS SUDO!!!"""

# Define the port on which the HTTP server will run
PORT = 8000

# Main function to orchestrate the process
def main():
    # Display script author and company information
    print("""
    ------------------------------------------
    |Author: Roy D. Williams                 |
    |Github: rwill97                         |
    |Company: Advanced Business Resources    |
    ------------------------------------------
    """)

    # Inform the user that Kismet will be run for data capture
    print('\n\n\nRunning Kismet for 5 minutes...')

    # Enable monitor mode on the wireless network adapter (e.g., wlan1)
    subprocess.run(["airmon-ng", "start", "wlan1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Start Kismet in the background, suppressing its output
    kismet_process = subprocess.Popen(["kismet"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Let Kismet run for 5 minutes to collect Wi-Fi data
    time.sleep(300)

    # Terminate the Kismet process after data collection
    kismet_process.terminate()
    kismet_process.wait()

    # Locate the Kismet-generated database file in the specified directory
    globbed_db_path = pathlib.Path('/home/pi/SSIDmapper').glob('*.kismet')
    db_path = str(next(globbed_db_path))

    # Extract SSIDs from the collected data
    ssids = grab_probes()

    # Fetch location data for the extracted SSIDs using the Wigle API
    results = get_location(ssids)
    return results

# Function to extract probed SSIDs from the Kismet database
def grab_probes():
    """This function connects to the Kismet DB file and extracts
       the probed SSIDs from the collected packets.
    """
    print('\nDissecting probes from Kismet...')

    # Locate the Kismet database file
    globbed_db_path = pathlib.Path('/home/pi/SSIDmapper').glob('*.kismet')
    db_path = str(next(globbed_db_path))

    ssids = []

    # Connect to the SQLite database created by Kismet
    con = sqlite3.connect(db_path)
    curs = con.cursor()

    # Query the database to get device information
    curs.execute('SELECT devmac, type, device FROM devices')
    rows = curs.fetchall()

    # Loop through query results to extract probed SSIDs
    for row in rows:
        raw_device_json = json.loads(str(row[2], errors='ignore'))

        # Check if the row contains probed SSID information
        if 'dot11.probedssid.ssid' in str(row):
            probed_ssid = raw_device_json["dot11.device"]["dot11.device.last_probed_ssid_record"]["dot11.probedssid.ssid"]

            # Ignore empty SSIDs
            if probed_ssid:
                ssids.append(probed_ssid)

    # Remove duplicate SSIDs
    ssids = list(set(ssids))

    return ssids

# Function to retrieve location data for SSIDs using the Wigle API
def get_location(probed_ssids):
    """This function takes a list of probed SSIDs and attempts to retrieve 
       location data from the Wigle API.
    """
    print('\nMaking API calls...\n')

    addresses = {}

    # Define API URL and credentials (replace with actual credentials)
    url = "https://api.wigle.net/api/v2/network/search"
    username = "YOUR API USERNAME"
    password = "YOUR API PASSWORD"
    headers = {
        "Accept": "application/json"
    }

    # Loop through each SSID and make an API request to Wigle
    for ssid in probed_ssids:
        params = {
            "onlymine": "false",
            "freenet": "false",
            "paynet": "false",
            "ssid": ssid
        }

        # Send a GET request to the API with the parameters and credentials
        response = requests.get(url, headers=headers, params=params, auth=HTTPBasicAuth(username, password))

        # Process the API response if successful
        if response.status_code == 200:
            data = response.json()

            # Extract and format location data from the API response
            for result in data.get("results", []):
                lat = result.get("trilat")
                lon = result.get("trilon")
                hn = result.get("housenumber")
                road = result.get("road")
                city = result.get("city")
                region = result.get("region")
                country = result.get("country")
                address = f"{hn} {road} {city}, {region} {country}"

                # Remove any 'None' values from the address string
                filtered_address = re.sub(r'\bNone\b\s*', '', address).strip()
                addresses[ssid] = filtered_address

        else:
            # Print the response code if the API call fails
            print(response.status_code)

    return addresses

# Cache the data collected from the main function
data_cache = main()

# Define a request handler class for the HTTP server
class MyHandler(http.server.SimpleHTTPRequestHandler):

    # Handle GET requests to serve different resources
    def do_GET(self):
        # Serve the index.html page for the root path
        if self.path == '/':
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            with open("index.html", "r", encoding="utf-8") as index:
                self.wfile.write(index.read().encode("utf-8"))

        # Serve the cached data as JSON for the '/data' path
        elif self.path == '/data':
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(data_cache, ensure_ascii=False).encode("utf-8"))

        # Serve the logo image for the '/logo.png' path
        elif self.path == '/logo.png':
            name = self.path[1:]
            nameFile = open(name, 'rb').read()
            mimetype = MimeTypes().guess_type(name)[0]
            self.send_response(200)
            self.send_header('Content-Type', mimetype)
            self.end_headers()
            self.wfile.write(nameFile)

        # Return a 404 error for any other paths
        else:
            self.send_error(404)

# Create and start the HTTP server
with socketserver.TCPServer(("", PORT), MyHandler) as httpd:
    print(f"Serving at port {PORT}")
    print("Press Ctrl+C to stop")
    httpd.serve_forever()
