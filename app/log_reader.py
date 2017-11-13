from flask import Flask, request, Response,jsonify
import urllib
import re

log_analysis_app = Flask(__name__)

#Log is placed into this directory
log_location = './log/CTF1.log'
#Regex for finding out the IPv4 addresses
ipRegex = re.compile('.*?'+'((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))(?![\\d])'+'.*?'+'((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))(?![\\d])',re.IGNORECASE|re.DOTALL)
#Stored in memory(dictionary) and arrays - Normally, we will put this into persistence storage
ipAddressesCount = {} 
ipAddressActions = {}
detectPossibleSQLi = []
detectPossibleExtFile = []
detectPossibleWebShell = []

#This function refreshes data with new log file (Scan for abnormally)
@log_analysis_app.route('/refreshData')
def parseAndLoadLog():
	count = 0
	print "Processing Started...Please wait a moment!"
	with open(log_location) as f:
		for line in f:
				count += 1
				requestURL = "Not Applicable"
				searchIP = ipRegex.search(line)
				#Gets Activities from each Request
				searchURL = re.findall('(http[^<]+)',line)
				statuscode = "200"
				if len(searchURL) > 0:
					splitURL = searchURL[0].split(" ")
					if len(splitURL) > 4:
							#This is the status code of the http request
							status = splitURL[-4]
							del splitURL[-4]
							del splitURL[-3]
							del splitURL[-2]
							del splitURL[-1]
					requestURL = ' '.join(splitURL)
				else:
					requestURL = searchURL
				activityInfo = line.split(" ")
				if searchIP:
						if searchIP.group(2) not in ipAddressesCount:
    							ipAddressesCount[searchIP.group(2)] = 1
    							#Scan requests for abnormally in terms of SQLi, File Extensions and Webshells
    							#Common SQL-statements (SQLi) that can hijack the tables
	    						if  "SELECT" in str(requestURL).upper() and "FROM" in str(requestURL).upper():
	    							detectPossibleSQLi.append({'attacker_ip':searchIP.group(2),'date':activityInfo[0],'time':activityInfo[1],'method':activityInfo[3],'response':activityInfo[4],'request':requestURL,'status':status,'sqli_type':'sqli_select'})
	    						elif "DELETE" in str(requestURL).upper() and "FROM" in str(requestURL).upper():
	    							detectPossibleSQLi.append({'attacker_ip':searchIP.group(2),'date':activityInfo[0],'time':activityInfo[1],'method':activityInfo[3],'response':activityInfo[4],'request':requestURL,'status':status,'sqli_type':'sqli_delete'})
	    						elif "UPDATE" in str(requestURL).upper() and "SET" in str(requestURL).upper():
	    							detectPossibleSQLi.append({'attacker_ip':searchIP.group(2),'date':activityInfo[0],'time':activityInfo[1],'method':activityInfo[3],'response':activityInfo[4],'request':requestURL,'status':status,'sqli_type':'sqli_update'})
	    						elif "DROP" in str(requestURL).upper() and "TABLE" in str(requestURL).upper():
	    							detectPossibleSQLi.append({'attacker_ip':searchIP.group(2),'date':activityInfo[0],'time':activityInfo[1],'method':activityInfo[3],'response':activityInfo[4],'request':requestURL,'status':status,'sqli_type':'sqli_drop'})
	    						elif "TRUNCATE" in str(requestURL).upper() and "TABLE" in str(requestURL).upper():
	    							detectPossibleSQLi.append({'attacker_ip':searchIP.group(2),'date':activityInfo[0],'time':activityInfo[1],'method':activityInfo[3],'response':activityInfo[4],'request':requestURL,'status':status,'sqli_type':'sqli_truncate'})
	    						elif ' OR ""="' in str(requestURL).upper():
	    							detectPossibleSQLi.append({'attacker_ip':searchIP.group(2),'date':activityInfo[0],'time':activityInfo[1],'method':activityInfo[3],'response':activityInfo[4],'request':requestURL,'status':status,'sqli_type':'sqli_or_equal'})
	    						elif " 1=1 " in str(requestURL).upper() :
	    							detectPossibleSQLi.append({'attacker_ip':searchIP.group(2),'date':activityInfo[0],'time':activityInfo[1],'method':activityInfo[3],'response':activityInfo[4],'request':requestURL,'status':status,'sqli_type':'sqli_get_all_info'})
	    						#Attackers use payloads
	    						if ".RAR" in str(requestURL).upper() or ".ZIP" in str(requestURL).upper() or ".DLL" in str(requestURL).upper()  or "WEB~1.CON" in str(requestURL).upper() or "HTACCE~1" in str(requestURL).upper():
	    							detectPossibleExtFile.append({'attacker_ip':searchIP.group(2),'date':activityInfo[0],'time':activityInfo[1],'method':activityInfo[3],'response':activityInfo[4],'request':requestURL,'status':status,'file_ext_type':'attached_payload'})

	    						#Attackers testing servers for web-shell attacks. (95% comes from php script)
	    						piggyBackScript = str(requestURL).lower().count("http")
	    						
	    						if "TEST CERTIFICATE INFO" in str(requestURL).upper():
	    							detectPossibleWebShell.append({'attacker_ip':searchIP.group(2),'date':activityInfo[0],'time':activityInfo[1],'method':activityInfo[3],'response':activityInfo[4],'request':requestURL,'status':status,'web_shells_type':'test_water'})
	    						elif piggyBackScript>=2 and requestURL != [] and ".PHP" in str(requestURL).upper():
	    							detectPossibleWebShell.append({'attacker_ip':searchIP.group(2),'date':activityInfo[0],'time':activityInfo[1],'method':activityInfo[3],'response':activityInfo[4],'request':requestURL,'status':status,'web_shells_type':'cross-site'})
    								
    							#Gets date, time, method(Get/Post/Put and etc)
    							ipAddressActions[searchIP.group(2)] = [[activityInfo[0],activityInfo[1],activityInfo[3],activityInfo[4],requestURL,status]]
    							
	    					else:
	    						ipAddressesCount[searchIP.group(2)] = ipAddressesCount[searchIP.group(2)] + 1
	    						#Common SQL-statements(SQLi) that can hijack the tables
	    						if  "SELECT" in str(requestURL).upper() and "FROM" in str(requestURL).upper():
	    							detectPossibleSQLi.append({'attacker_ip':searchIP.group(2),'date':activityInfo[0],'time':activityInfo[1],'method':activityInfo[3],'response':activityInfo[4],'request':requestURL,'status':status,'sqli_type':'sqli_select'})
	    						elif "DELETE" in str(requestURL).upper() and "FROM" in str(requestURL).upper():
	    							detectPossibleSQLi.append({'attacker_ip':searchIP.group(2),'date':activityInfo[0],'time':activityInfo[1],'method':activityInfo[3],'response':activityInfo[4],'request':requestURL,'status':status,'sqli_type':'sqli_delete'})
	    						elif "UPDATE" in str(requestURL).upper() and "SET" in str(requestURL).upper():
	    							detectPossibleSQLi.append({'attacker_ip':searchIP.group(2),'date':activityInfo[0],'time':activityInfo[1],'method':activityInfo[3],'response':activityInfo[4],'request':requestURL,'status':status,'sqli_type':'sqli_update'})
	    						elif "DROP" in str(requestURL).upper() and "TABLE" in str(requestURL).upper():
	    							detectPossibleSQLi.append({'attacker_ip':searchIP.group(2),'date':activityInfo[0],'time':activityInfo[1],'method':activityInfo[3],'response':activityInfo[4],'request':requestURL,'status':status,'sqli_type':'sqli_drop'})
	    						elif "TRUNCATE" in str(requestURL).upper() and "TABLE" in str(requestURL).upper():
	    							detectPossibleSQLi.append({'attacker_ip':searchIP.group(2),'date':activityInfo[0],'time':activityInfo[1],'method':activityInfo[3],'response':activityInfo[4],'request':requestURL,'status':status,'sqli_type':'sqli_truncate'})
	    						elif ' OR ""="' in str(requestURL).upper():
	    							detectPossibleSQLi.append({'attacker_ip':searchIP.group(2),'date':activityInfo[0],'time':activityInfo[1],'method':activityInfo[3],'response':activityInfo[4],'request':requestURL,'status':status,'sqli_type':'sqli_or_equal'})
	    						elif " 1=1 " in str(requestURL).upper() :
	    							detectPossibleSQLi.append({'attacker_ip':searchIP.group(2),'date':activityInfo[0],'time':activityInfo[1],'method':activityInfo[3],'response':activityInfo[4],'request':requestURL,'status':status,'sqli_type':'sqli_get_all_info'})
	    						
	    						#Attackers use payloads
	    						if ".RAR" in str(requestURL).upper() or ".ZIP" in str(requestURL).upper() or ".DLL" in str(requestURL).upper()  or "WEB~1.CON" in str(requestURL).upper() or "HTACCE~1" in str(requestURL).upper():
	    							detectPossibleExtFile.append({'attacker_ip':searchIP.group(2),'date':activityInfo[0],'time':activityInfo[1],'method':activityInfo[3],'response':activityInfo[4],'request':requestURL,'status':status,'file_ext_type':'attached_payload'})

	    						#Attackers testing servers for web-shell attacks.  (95% comes from php script)
	    						piggyBackScript = str(requestURL).lower().count("http")
	    						
	    						if "TEST CERTIFICATE INFO" in str(requestURL).upper():
	    							detectPossibleWebShell.append({'attacker_ip':searchIP.group(2),'date':activityInfo[0],'time':activityInfo[1],'method':activityInfo[3],'response':activityInfo[4],'request':requestURL,'status':status,'web_shells_type':'test_water'})
	    						elif piggyBackScript>=2 and requestURL != [] and ".PHP" in str(requestURL).upper():
	    							detectPossibleWebShell.append({'attacker_ip':searchIP.group(2),'date':activityInfo[0],'time':activityInfo[1],'method':activityInfo[3],'response':activityInfo[4],'request':requestURL,'status':status,'web_shells_type':'cross-site'})
    								
	    						ipAddressActions[searchIP.group(2)].append([activityInfo[0],activityInfo[1],activityInfo[3],activityInfo[4],requestURL,status])
	
	print "Processing End. Total Line Count:" +str(count)    						
	return Response("{'data_refreshed':true}", status=200, mimetype='application/json')

#This function gets all unique IP addresses and respective count
@log_analysis_app.route('/uniqueIPAddresses')
def retrieveIPInformation():
	arrOfIPAddress = []
	allUniqueKeys = ipAddressesCount.keys()

	for key in allUniqueKeys:
		
		arrOfIPAddress.append({'ip_address':str(key),'request_count':str(ipAddressesCount[key])})

	return Response("{'list_of_unique_ip':"+str(arrOfIPAddress)+"}", status=200, mimetype='application/json')

#This function gets all risk detected for SQLi, file Ext and webshells
@log_analysis_app.route('/detectedAnormalies')
def retrieveDetectedAnormalies():

	return Response("{'detected_possible_sqli':"+str(detectPossibleSQLi)+",'detected_possible_webshells':"+str(detectPossibleWebShell)+",'detected_possible_file_ext':"+str(detectPossibleExtFile)+"}", status=200, mimetype='application/json')

#This function retrieves all IP Activities based Unique IP found (Includes country info)
@log_analysis_app.route('/getIPActivity/<ip>')
def getIPActivity(ip):
	if ip in ipAddressActions:
		allActions = ipAddressActions[ip]
		
		#Call webservice for location of IP Address
		geourl = "https://geoip-db.com/jsonp/" + str(ip)
		res = urllib.urlopen(geourl)
		data = res.read().replace("callback(", "").replace(")", "")
		
		#Store all actions in readable formatting
		formattedActions = []

		for eachActivity in allActions:
			formattedActions.append({'date':eachActivity[0],'time':eachActivity[1],'method':eachActivity[2],'response':eachActivity[3],'request':eachActivity[4],'status_code':eachActivity[5]})

		return Response("{'country_data':"+str(data)+",'ip_activities':"+str(formattedActions)+"}", status=200, mimetype='application/json')
	else:
		return Response("{'ip_activities':'NIL'}", status=200, mimetype='application/json')

if __name__ == '__main__':
    log_analysis_app.run(debug=True,host='0.0.0.0')