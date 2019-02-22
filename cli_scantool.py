import argparse
import getpass
import sys
import datetime
import json
import requests
import getpass
import time
import re

class SecurityCenterAPI(object):
	def __init__(self, username: str, password: str, url: str):
		self.username = username
		self.password = password
		self.url = url
		self.cookie = None
		self.token = None
		self.assets = []
		self.dash = '-' * 40

	def build_url(self, resource):

		return '{0}{1}'.format(self.url, resource)

	def connect(self, method: str, resource: str, data: dict = None, headers: dict = None):
		if headers is None:
			headers = {'Content-type': 'application/json','X-SecurityCenter': str(self.token)}

		if data is not None:
			data = json.dumps(data)

		if method == "POST":
			resp = requests.post(self.build_url(resource), data=data, headers=headers, cookies=self.cookie,verify=False)

		elif method == "DELETE":
			resp = requests.delete(self.build_url(resource), data=data, headers=headers, cookies=self.cookie,verify=False)

		elif method == 'PATCH':
			resp = requests.patch(self.build_url(resource), data=data, headers=headers, cookies=self.cookie,verify=False)

		else:
			resp = requests.get(self.build_url(resource), data=data, headers=headers, cookies=self.cookie,verify=False)

		if resp.headers.get('set-cookie') is not None:
			match = re.findall("TNS_SESSIONID=[^,]*", resp.headers.get('set-cookie'))
			self.cookie = match[1]

		return resp

	def login(self):
		headers = {'Content-Type': 'application/json'}
		login = {'username': self.username, 'password': self.password}
		data = self.connect('POST', '/rest/token', data=login, headers=headers)
		self.cookie = data.cookies
		self.token = data.json()['response']['token']

		return self.cookie, self.token

	def policy_dump(self):
		policies = self.connect("GET", '/rest/policy')
		print("\nPolicies Available:")
		print(self.dash)
		print('{:<10s}{:<12s}'.format("ID","name"))
		print(self.dash)
		for policy in policies.json()['response']['usable']:
			print('{:<10s}{:^12s}'.format(policy['id'],policy['name']))

	def credential_dump(self): 
		credentials = self.connect("GET", '/rest/credential')
		print("\nCredentials Available:")
		print(self.dash)
		print('{:<10s}{:^12s}{:<24s}'.format("type","ID","name"))
		print(self.dash)
		for credential in credentials.json()['response']['usable']:
			print('{:<10s}{:^12s}{:<24s}'.format(credential['type'],credential['id'],credential['name']))

	def create_scan(self,results):
		
		timestamp = time.strftime('%Y%m%d' + 'T' + '%H%M%S')
		jsonobj = {"name": results.scanname ,"description":"","context":"","status":-1,"createdTime":0,"modifiedTime":0,"groups":[],"repository":{"id":"17"},"schedule":{"start":"TZID=America/New_York:"+ timestamp,"repeatRule":"FREQ=NOW;INTERVAL=1","type":"now"},"dhcpTracking":"true","emailOnLaunch":"false","emailOnFinish":"false","reports":[],"type":"policy","policy":{"id": results.policy },"zone":{"id":-1},"timeoutAction":"import","rolloverType":"template","scanningVirtualHosts":"false","classifyMitigatedAge":0,"assets":[],"ipList":results.ip_address,"credentials":credlist,"maxScanTime":"unlimited"}
		resp = self.connect("POST",'/rest/scan',data=jsonobj)
		if resp.json()['error_msg']:
			print(resp.json()['error_msg'])
		else:
			return resp.json()['response']['scanResultID']


	def retrieve_scan_results(self,scanid,results):
		status = None
		print("Initializing...")
		filedate = '{0:%Y-%m-%d}'.format(datetime.datetime.now())
		filename = "scan_" + filedate + "_IP_" + results.ip_address.replace(".","_") + ".csv"
		while status != 'ready':
			scanstatus = sc.connect("GET", '/rest/scanResult/' + scanid)
			try:

				completed = int(scanstatus.json()['response']['progress']['completedChecks'])
				total = int(scanstatus.json()['response']['progress']['totalChecks'])
				progress = int(completed / total * 100)
				sys.stdout.write("\r" + str(progress) + "% Complete")
			except: 
				pass
			if scanstatus.json()['response']['status'] == 'Completed' and scanstatus.json()['response']['importStatus'] == 'Finished':
				status = 'ready'
			time.sleep(15)

		print("\nPreparing " + filename + "...")
		data = {"query":{"name":"","description":"","context":"","status":-1,"createdTime":0,"modifiedTime":0,"group":{"id":0,"name":"Administrator"},"groups":[],"type":"vuln","tool":"vulndetails","sourceType":"individual","startOffset":0,"endOffset":1000,"filters":[{"id":"severity","filterName":"severity","operator":"=","type":"vuln","isPredefined":"true","value":"2,3,4"}],"vulnTool":"vulndetails","scanID":scanid,"view":"all","scanName":results.scanname},"sourceType":"individual","scanID":scanid,"columns":[{"name":"pluginID"},{"name":"pluginName"},{"name":"familyID"},{"name":"severity"},{"name":"ip"},{"name":"protocol"},{"name":"port"},{"name":"exploitAvailable"},{"name":"repositoryID"},{"name":"macAddress"},{"name":"dnsName"},{"name":"netbiosName"},{"name":"pluginText"},{"name":"firstSeen"},{"name":"lastSeen"},{"name":"exploitFrameworks"},{"name":"synopsis"},{"name":"description"},{"name":"solution"},{"name":"seeAlso"},{"name":"riskFactor"},{"name":"stigSeverity"},{"name":"baseScore"},{"name":"cvssV3BaseScore"},{"name":"temporalScore"},{"name":"cvssV3TemporalScore"},{"name":"cvssVector"},{"name":"cvssV3Vector"},{"name":"cpe"},{"name":"cve"},{"name":"bid"},{"name":"xref"},{"name":"vulnPubDate"},{"name":"patchPubDate"},{"name":"pluginPubDate"},{"name":"pluginModDate"},{"name":"exploitEase"},{"name":"checkType"},{"name":"version"}],"type":"vuln"}
		resp = self.connect("POST",'/rest/analysis/' + '/download', data=data)
		status = 'ready'
		content = resp.content
		with open(filename,'wb') as file:
			file.write(content)
		file.close()

		

if __name__ == '__main__':
	#stupid ssl issue
	requests.packages.urllib3.disable_warnings()
	credlist =[]


	#config parser 
	parser = argparse.ArgumentParser()
	parser.add_argument("--ip", help="IP Addresses to be scanned. Can be a single IP or a comma separated list", action="store", dest="ip_address", required=False)
	parser.add_argument("--policy", help="Use if a custom policy will be used", action="store", dest="policy", required=False)
	parser.add_argument("--username", help="Username", action="store", dest="username", required=True)
	parser.add_argument("--scanname", help="Scan name", action="store", dest="scanname", required=False)
	parser.add_argument("--url", help="URL", action="store", dest="url", required=True)
	parser.add_argument("--policy-dump", help="Show available policies", action="store_true", dest="policy_dump", required=False)
	parser.add_argument("--credential-dump", help="Show available credentials", action="store_true", dest="credential_dump", required=False)
	parser.add_argument("--credentials", help="Comma seperated list of credentials or 'none'", action="store", dest="credentials", required=False)
	results = parser.parse_args()


	#set all security center params
	url = results.url
	username = results.username
	password = getpass.getpass('Password: ')
	print("Logging in...")

	# This calls the login function and passes it your credentials, no need to modify this.
	sc = SecurityCenterAPI(url=url, username=username, password=password)
	cookie, token = sc.login()
	print('Login Successful')

	if results.policy_dump == True:
		sc.policy_dump()

	if results.credential_dump == True:
		sc.credential_dump()
	#make sure they filled out the policy switch
	if results.policy == None:
		results.policy = input("Please eneter a policy ID: ")

	#make sure they filled out the credentials
	if results.credentials == None:
		results.credentials = input("Please enter a comma seperated list of credentials or type 'none': ")
		if str(results.credentials).lower() == 'none':
			pass
		else:
			credentials = results.credentials.split(',')
			for credential in credentials:
				cred = {'id': int(credential)}
				credlist.append(cred)

	#creates a scan and then watches until the scan is finished and downloads the result 	
	scanid = sc.create_scan(results)
	if scanid != None:
		sc.retrieve_scan_results(scanid,results)

