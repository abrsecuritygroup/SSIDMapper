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

PORT = 8000

def main():

    print("""
    ------------------------------------------
    |Author: Roy D. Williams                 |
    |Github: rwill97                         |
    |Company: Advanced Business Resources    |
    ------------------------------------------
    """)
    
    print('\n\n\nRunning Kismet for 5 minutes...')

    #Put alfa card in monitor mode
    subprocess.run(["airmon-ng", "start", "wlan1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    #Run Kismet and send stdout and stderror to dev null.
    kismet_process = subprocess.Popen(["kismet"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    #Let Kismet run for 5 minutes and kill the process
    time.sleep(300)
    kismet_process.terminate()
    kismet_process.wait()

    #Find the file path to the generated Kismet DB file
    globbed_db_path = pathlib.Path('/home/pi/SSIDmapper').glob('*.kismet')
    db_path = str(next(globbed_db_path))

    #Extract probe requests
    ssids = grab_probes()

    #Search for location information
    results = get_location(ssids)
    return results

def grab_probes():
    """This function will connect to the Kismet DB file and extract
       the probed SSIDs from the collected packets
    """
    print('\nDissescting probes from kismet...')

    globbed_db_path = pathlib.Path('/home/pi/SSIDmapper').glob('*.kismet')
    db_path = str(next(globbed_db_path))

    ssids = []
    con = sqlite3.connect(db_path)
    curs = con.cursor()
    curs.execute('SELECT devmac, type, device FROM devices')
    rows = curs.fetchall()
    
    #Loop through results from SQL query and extract the probed SSIDs
    for row in rows:
        raw_device_json = json.loads(str(row[2], errors='ignore'))
        
        if 'dot11.probedssid.ssid' in str(row):
            probed_ssid = raw_device_json["dot11.device"]["dot11.device.last_probed_ssid_record"]["dot11.probedssid.ssid"]
            
            if probed_ssid == '':
                pass
            
            else:
                ssids.append(probed_ssid)

    ssids = list(set(ssids))

    return ssids


def get_location(probed_ssids):

    """This function will take a list of probed SSIDs and attempt to retrieve 
       locational data from the Wigle API. """
    
    print('\nMaking API calls...\n')

    addresses = {}

    #Set url variables. Change the API key information to match your API credentials.
    url = "https://api.wigle.net/api/v2/network/search"
    username = 	"YOUR API USERNAME"
    password = "YOUR API PASSWORD"
    headers = {
            "Accept": "application/json"
            }
    
    #Set parameters for API request
    for ssid in probed_ssids:
        params = {
                "onlymine": "false",
                "freenet": "false",
                "paynet": "false",
                "ssid": ssid
                }

        #Make API Call
        response = requests.get(url, headers=headers, params=params, auth=HTTPBasicAuth(username, password))
        
        #Parse JSON data returned from API
        if response.status_code == 200:
            data = response.json()

            for result in data.get("results", []):
                lat = result.get("trilat")
                lon = result.get("trilon")
                hn = result.get("housenumber")
                road = result.get("road")
                city = result.get("city")
                region = result.get("region")
                country = result.get("country")
                address = f"{hn} {road} {city}, {region} {country}"
                
                #Remove the word 'None' from addresses.
                filtered_address = re.sub(r'\bNone\b\s*', '', address).strip()
                addresses[ssid] = filtered_address
                
        else:
            print(response.status_code)

    return addresses

data_cache = main()

class MyHandler(http.server.SimpleHTTPRequestHandler):
   
    #Handle the different possible GET requests
    def do_GET(self):
        if self.path == '/':

            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            with open("index.html", "r", encoding="utf-8") as index:

                self.wfile.write(index.read().encode("utf-8"))
        
        elif self.path == '/data':

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(data_cache, ensure_ascii=False).encode("utf-8"))

        elif self.path == '/logo.png':
            name = self.path[1:]
            nameFile = open(name, 'rb').read()
            mimetype = MimeTypes().guess_type(name)[0]
            self.send_response(200)
            self.send_header('Content-Type', mimetype)
            self.end_headers()
            self.wfile.write(nameFile)

        else:
            self.send_error(404)


with socketserver.TCPServer(("", PORT), MyHandler) as httpd:
    
    print(f"Serving at port {PORT}")
    print("Press Ctrl+C to stop")
    httpd.serve_forever()

    
