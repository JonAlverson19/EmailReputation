from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.firefox_binary import FirefoxBinary
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from fnmatch import fnmatch
from time import sleep, time
import os

_headless = True #set to False if inspecting the browser is required

_emails = {} # {email_name: ip}
_reputations = {} # {email_name: [email rep, web rep, threat category, domain, owner, hostname]}
_sites = ["https://talosintelligence.com/","https://www.ipalyzer.com/","https://www.riskiq.com/"] #support for other sources not yet implemented
_attatchments = {} # {email_name: {file_name: base64 first line of file}}
_images = {} # {email_name: img src}
_knownSignatures = {"JVBERi0": "pdf", "R0lGODlh": "gif", "R0lGODdh": "gif", "iVBORw0KGgo": "png", "/9j/2w==": "jpg", "TVo=": "exe", "UEsDBA==": "zip", "f0VMRg==": "elf" , "0M8R4KGxGuE=": "microsoft office file (doc, ppt, etc)", "dXN0YXIAMDA=": "tar", "dXN0YXIgIAA=": "tar", "N3q8rycc": "7zip", "H4s=": "gzip", "PD94bWwg": "xml", "UmVjZWl2ZWQ=": "eml"
}
_emailSignatures = {} # {email_name: 

firefoxOptions = Options()
if _headless:
	firefoxOptions.add_argument("--headless")
driver = webdriver.Firefox(options=firefoxOptions)

def check_signature(b64):
	for sig in _knownSignatures.keys():
		if b64.startswith(sig):
			return _knownSignatures[sig];
	return "unknown"

def find_reputation():
	#Parse site specific elements to retrieve different strings
	owner_elems = driver.find_elements_by_xpath("//div[contains(@id, 'owner-data-wrapper')]")
	email_elems = driver.find_elements_by_xpath("//div[contains(@id, 'email-data-wrapper')]")
	
	category = ""
	domain = ""
	owner = ""
	
	if len(owner_elems) > 0:
		if "DOMAIN" in owner_elems[0].text:
			domain = owner_elems[0].text.split("DOMAIN ")[1].split('\n')[0]
		if "NETWORK OWNER" in owner_elems[0].text:
			owner = owner_elems[0].text.split("NETWORK OWNER ")[1].split('\n')[0]
		if "HOSTNAME" in owner_elems[0].text:	
			hostname = owner_elems[0].text.split("HOSTNAME ")[1].split('\n')[0]
			if hostname == owner_elems[0].text.split("IP ADDRESS ")[1].split('\n')[0]:
				hostname = ""
			
	if len(email_elems) > 0:
		if "REPUTATION" in email_elems[0].text:
			if "THREAT CATEGORY" in email_elems[0].text:
				category = email_elems[0].text.split("THREAT CATEGORY ")[1].split("\n")[0]
			if "-" == email_elems[0].text.split("EMAIL REPUTATION ")[1].split('\n')[0]:
				return ["Neutral", email_elems[0].text.split("Legacy)\n")[1].split('|')[0], category, domain, owner, hostname]
			else:
				return [email_elems[0].text.split("EMAIL REPUTATION ")[1].split('\n')[0], email_elems[0].text.split("Legacy)\n")[1].split('|')[0], category, domain, owner, hostname]
	
	return ["Not Found", "Not Found", "", "", "", ""] #return default values if element not found


def browse(email):
		if _headless:
			driver.get(_sites[0])
		else: #use a new window for each search
			if _emails.keys().index(email, 0, len(_emails.keys())) == 0:
				driver.get(_sites[0])
			else:
				driver.execute_script("window.open('');")
				driver.switch_to.window(driver.window_handles[-1])
				driver.get(_sites[0])
		
		#enter the ip into the search field
		elem = driver.find_element_by_name("search")
		elem.clear()
		elem.send_keys(_emails[email] + Keys.RETURN)
		
		stopwatch = 0
		while "Reputation Lookup" not in driver.title and stopwatch <= 10:
			sleep(1) #wait for DDoS protection to complete
			stopwatch += 1
		
		if stopwatch > 10:
			print("Timeout while browsing for " + email)
			_reputations[email] = ["Not Found", "Not Found", "", "", "", ""]
			driver.close()
			return
			
		sleep(0.5) #give time for page to load tables
		
		_reputations[email] = find_reputation()
		
		if _headless: #close window once information is found to save memory
			driver.execute_script("window.open('');")
			driver.close()
			driver.switch_to.window(driver.window_handles[0])
			

def main():
	#find all email files in current directory
	for file in os.listdir("."):
		if fnmatch(file, "*.eml"):
			_emails[file] = ""
	print("Found " + str(len(_emails.keys())) + " emails.\nFinding IPs...")
	
	#find the sender's ip in each email file
	for email in _emails.keys():
		incompleteLink = False
		attatchmentFound = False
		mimeTypeLine = False
		previousAttatchment = ""
		with open(email, 'r') as f:
			lines = f.readlines()
			for line in lines:
				if 'client-ip' in line:
					_emails[email] = line.split('client-ip=')[1].split(';')[0]
					
				if mimeTypeLine:
					_attatchments[email][previousAttatchment] = line
					previousAttatchment = ""
					mimeTypeLine = False
					attatchmentFound = False
					
				if attatchmentFound and line.startswith("\n"):
					mimeTypeLine = True
				
				if "Content-Type: " in line and "name" in line:
					attatchmentFound = True
					previousAttatchment = line.split("\"")[1]
					if email in _attatchments.keys():
						if line.split('\"')[1] in _attatchments[email].keys(): #if the attatchment has the same name as a previous one, append epoch
							_attatchments[email][line.split('\"')[1].join(time())] = ""
						else:
							_attatchments[email][line.split("\"")[1]] = ""
					else:
						_attatchments[email] = {}
						_attatchments[email][line.split("\"")[1]] = ""
				
				if incompleteLink:
					if '\"' in line:
						_images[email][-1] = _images[email][-1] + line.split('\"')[0]
						incompleteLink = False
					else:
						_images[email][-1] = _images[email][-1] + line
				
				if "img src" in line:
					line = line.split("<img src")[1]
					if '>' not in line:
						incompleteLink = True
						line = line.split('=\n')[0]
					if email in _images.keys():
						_images[email].append(line.split("\"")[1])
					else:
						_images[email] = [line.split("\"")[1]]
				
					
	#print("Starting browser...")
	i = 0
	for email in _emails.keys():		
		#add suffix for ordinal representation. adapted from florian brucker on stackoverflow.
		suffix = ['th', 'st', 'nd', 'rd', 'th'][min((i+1) % 10, 4)]
		if 11 <= (i+1)%100 <= 13: #teen numbers all end in th
			suffix = 'th'
			
		print("\nFinding reputation of " + str(i+1) + suffix +" email sender...")

		browse(email)
		
		

		#this may happen if site did not load in time. Need to overhaul code to specificially wait for an element rather than an amount of time.
		if "Not Found" in _reputations[email]: 
			#elements may not being found on first pass. Could be due to the site being cached after the first attempt.
			browse(email)
			
		if "Not Found" in _reputations[email]:
			print("Could not find information on " + email)
			continue
			
		print("Information on IP source from " + str(email))
		print("Email reputation: " + _reputations[email][0])
		print("Web reputation: " + _reputations[email][1])
		if _reputations[email][2] != "":
			print("Malicious activity congruent with: " + _reputations[email][2])
		if _reputations[email][3] != "":
			print("Domain: " + _reputations[email][3])
		if _reputations[email][4] != "":
			print("Owner: " + _reputations[email][4])
		if _reputations[email][5] != "":
			print("Hostname: " + _reputations[email][5])	
		
		if email in _images.keys():
			for img in _images[email]:
				print("Image link: " + img)
				
		if email in _attatchments.keys():
			for attatchmentName in _attatchments[email]:
				attatchmentType = check_signature(_attatchments[email][attatchmentName])
				print(attatchmentName + " appears to be a " + attatchmentType)
			
		i += 1	
		
	if _headless: #close final window
		driver.close() 
	else: #wait for user to finish inspecting browser
		print("\nPress enter to close tabs\n")
		input()

		win_num = len(driver.window_handles)
		for window in range(win_num):
			driver.switch_to.window(driver.window_handles[0])
			driver.close()

	
if __name__ == "__main__":
	main()