# EmailReputation
Searches current directory for emails in the .eml file format and pulls ips from them to retrieve the reputation data on that ip. These files can be obtained from gmail by opening the email and selecting 'show original' from the triple dot more button. 
Note: This method does require opening the email first, which may not be safe. Seek other analysis methods if you don't trust an email before opening it.

# Requirements
Uses the selenium geckodriver for firefox. Firefox must be in the default location. The correct version of geckodriver for your firefox version must be installed and added to system PATH. The selenium package must be installed. 
```bash
pip install selenium
```

# Build
This was locally built and tested on Python 3.8 with selenium 3.141.0 and geckodriver 0.26.0

# Run
Simply call
```bash
python email_reputation.py
```
If you want to get a peek behind the scenes, or gather information yourself, edit email_reputation.py and set 
```python
headless = False
```
This will prevent the program from closing out the firefox tab once a search is complete.

# Disclaimer
I do not own the site that is checking the ip addresses and do not guarantee that an email is safe simply because it returns a positive reputation.
