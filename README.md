# SSIDMapper
  This project is a POC that can be used by information security professionals, technical surveillance professionals, and hobbyists alike. The intent is to demonstrate to less technical customers or people in general just how much personal information can be derived from their mobile devices (phones, laptops, tablets) by running simple passive 802.11 collection and utilizing publicly available databases (like Wigle). 

  We use a mixture of Kismet, Wigle, Python, Javascript, and HTML to correlate captured probed SSIDs to physical addresses and display the results on a webpage. The Python script will run Kismet for a chosen period of time (e.g. 5 minutes), extract probed SSIDs from the generated .kismet database file, and use the Wigle API to find physical addresses that have been correlated to those SSIDs. It then runs a simple HTTP server using an HTML and Javascript file to display a chart clearly matching results from probed SSIDs and addresses. The Javascript and HTML file is very minimal to provide room for extreme flexability so anyone can tailor it to their organizational or personal needs.

  While developing this project, we used a Raspberry Pi 4B and Alfa card for collection. These are two relatively inexpensive pieces of hardware, further demonstrating that an even an unsophisticated adversary can do this. It is not required to use a Raspberry Pi 4. You can run this on any Linux based platform, but the Raspberry Pi 4 demonstrates something that an adversary would use for discreet 802.11 collection. 

  You will also need API keys from Wigle, which can easily be obtained free of charge by visiting their website. Wigle throttles the use of their API and increases the amount of requests per day. The longer you have an account, the more API calls you will be able to make.

  When downloading Kismet onto your device, be sure to follow the instructions for your chosen flavor of Linux at https://www.kismetwireless.net/packages/. 

```console
pi@pi:~ $ git clone https://github.com/abrsecuritygroup/SSIDMapper && cd SSIDMapper
pi@pi:~ $ chmod +x SSIDmapper.py
```
Attach your Alfa Card and let the script do the rest.
```console
pi@pi:~ $ sudo ./SSIDmapper.py
```
When the script is done running, open a webpage at http://localhost:8000. A chart like the one below will be displayed on the webpage.

![image](https://github.com/user-attachments/assets/531143ad-338b-4619-ad95-62fef34ccbe1)



