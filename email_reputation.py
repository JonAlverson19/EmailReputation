from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.firefox_binary import FirefoxBinary
from selenium.webdriver.firefox.options import Options
from fnmatch import fnmatch
from time import sleep
import os

headless = True #set to False if inspecting the browser is required

_emails = {}
_reputations = {}
sites = ["https://talosintelligence.com/","https://www.ipalyzer.com/","https://www.riskiq.com/"] #support for other sources not yet implemented


firefoxOptions = Options()
if headless:
	firefoxOptions.add_argument("--headless")
driver = webdriver.Firefox(options=firefoxOptions)


def find_reputation(element_id):
	#Parse site specific elements to retrieve different strings
	elems = driver.find_elements_by_id(element_id)
	category = ""
	if len(elems) > 0:
		if "REPUTATION" in elems[0].text:
			if "THREAT CATEGORY" in elems[0].text:
				category = elems[0].text.split("THREAT CATEGORY ")[1].split("\n")[0]
			if "-" == elems[0].text.split("EMAIL REPUTATION ")[1].split('\n')[0]:
				return ["Neutral", elems[0].text.split("Legacy)\n")[1].split('|')[0], category]
			else:
				return [elems[0].text.split("EMAIL REPUTATION ")[1].split('\n')[0], elems[0].text.split("Legacy)\n")[1].split('|')[0], category]


def browse():
	i = 0
	for email in _emails.keys():
		_reputations[email] = ["Not Found", "Not Found", ""] #Prep dict with default values
		
		#add suffix for ordinal representation. adapted from florian brucker on stackoverflow.
		suffix = ['th', 'st', 'nd', 'rd', 'th'][min((i+1) % 10, 4)]
		if 11 <= (i+1)%100 <= 13: #teen numbers all end in th
			suffix = 'th'
			
		print("Finding reputation of " + str(i+1) + suffix +" email sender...")

		if headless:
			driver.get(sites[0])
		else: #use a new window for each search
			if i == 0:
				driver.get(sites[0])
			else:
				driver.execute_script("window.open('');")
				driver.switch_to.window(driver.window_handles[i])
				driver.get(sites[0])
		
		#enter the ip into the search field
		elem = driver.find_element_by_name("search")
		elem.clear()
		elem.send_keys(_emails[email] + Keys.RETURN)
		
		while "Reputation Lookup" not in driver.title:
			sleep(1) #wait for DDoS protection to complete
			
		sleep(0.5) #give time for page to load tables
		
		_reputations[email] = find_reputation("email-data-wrapper")
		i+=1
		
		if headless: #close window once information is found to save memory
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
		with open(email, 'r') as f:
			lines = f.readlines()
			for line in lines:
				if 'client-ip' in line:
					_emails[email] = line.split('client-ip=')[1].split(';')[0]
					break
		
	print("Starting browser...")
	browse()
	
	for email in _emails.keys():
		if email not in _reputations.keys(): #this may happen if site did not load in time. Need to overhaul code to specificially wait for an element rather than an amount of time.
			print("Could not find information on " + email + ". You can try again")
			continue
		print("\nIP source from " + str(email))
		print("Email reputation: " + _reputations[email][0])
		print("Web reputation: " + _reputations[email][1])
		if _reputations[email][2] != "":
			print("Malicious activity congruent with: " + _reputations[email][2])
			
	if headless: #close final window
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