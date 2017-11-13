# Log-Reader

A flaskpy-docker implementation to read logs and detect Anormalies(SQLi,File-Ext,Web-shell Attacks)

Kindly replace the empty log file(CTF1.log).

## Log-Reader Web API 

Load Log Data by curling `http://localhost:5000/refreshData`

After log (CTF1.log) has been parsed into the Log-Reader app, you could utilise 3 webservices.
The returns will be in JSON format.
<br>
To get a list of unique IP Addresses(With Request Count) from Log file : `http://localhost:5000/uniqueIPAddresses`
<br><br>
To get a list of Log Activities associated with a particular IP Address(With Location from Geo-IP API) : `http://localhost:5000/getIPActivity/<IP Address>` <br>
A sample call : `http://localhost:5000/getIPActivity/52.122.3.64`
<br><br>
To get a list of Anormalies from log file : `http://localhost:5000/detectedAnormalies` 

## Requirements

- [Docker CE](https://www.docker.com/)
- [Python 2.7](https://www.python.org/)
- Ubuntu 14.04

## Installation

1. Clone the repository into a ubuntu instance
2. Replace the empty log file in `app/log/CTF1.log` with real `CTF1.log`
3. Move into `app` directory and build docker image through `sudo docker build -t log-reader:latest`
4. Run the compiled docker image and map it to tcp port 5000 via `sudo docker run -d -p 5000:5000 log-reader`
5. Check if your docker image is running : `sudo docker ps`
6. Open port 80, 443, 5000 
7. View at `http://Instance IP:5000/refreshData` or Curl to `http://localhost:5000/refreshData` (Loads Log)
8. After data is being loaded, all three webservices will be up and running

## Screenshots

Screenshots are being stored inside `screenshots` folder.

