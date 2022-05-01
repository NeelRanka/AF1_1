import subprocess
#print(subprocess.check_output(['nslookup', 'google.com']))
import os
import sys

OSallowed = {
			'0': 1, '1': 1, '2': 1, '3': 1, '4': 1, '5': 1, '6': 1, '7': 1, '8': 1, '9': 1,
			'a': 1, 'b': 1, 'c': 1, 'd': 1, 'e': 1, 'f': 1, 'g': 1, 'h': 1, 'i': 1, 'j': 1,
			'k': 1, 'l': 1, 'm': 1, 'n': 1, 'o': 1, 'p': 1, 'q': 1, 'r': 1, 's': 1, 't': 1,
			'u': 1, 'v': 1, 'w': 1, 'x': 1, 'y': 1, 'z': 1, 'A': 1, 'B': 1, 'C': 1, 'D': 1,
			'E': 1, 'F': 1, 'G': 1, 'H': 1, 'I': 1, 'J': 1, 'K': 1, 'L': 1, 'M': 1, 'N': 1,
			'O': 1, 'P': 1, 'Q': 1, 'R': 1, 'S': 1, 'T': 1, 'U': 1, 'V': 1, 'W': 1, 'X': 1,
			'Y': 1, 'Z': 1, '-': 1, '.': 1, '_': 1, ':': 1, "/": 1
			}



#OK
def subfinder(domain):
	# print("\n\nRunning Subfinder")
	# print("---------------------")
	command = "subfinder --silent -d '{}'".format(domain)        #--silent flag to only show the subdomains as the output
	subfinder = os.popen(command).read()            # simply append the to the previous output, no processing required 
	# input("\npython3 subfinder output : \n"+subfinder+"\n-----------------------------------------")
	return(subfinder.split())

#OK
def assetfinder(domain):
	# print("\n\nRunning AssetFinder")
	# print("-----------------------")
	command = "assetfinder '{}'".format(domain)
	assetfinder = os.popen(command).read()          # simply append the to the previous output, no processing required
	# input("python3 Assetfinder output \n"+assetfinder+"\n-------------------------------------")
	return(assetfinder.split())


def findRelevantSubdomains(subdomains,mainDomain):
	OK,NotOk = [], []
	for subdomain in subdomains:
		OK.append(subdomain) if mainDomain in subdomain else NotOk.append(subdomain)
	return( (OK,NotOk) )#---------------------------------------------------------------------------------------



#takes list of domains => httprobe => use (http only to avoid duplicates) to find JS files 
#OK
def findJSFiles(domains):
	global httpDomainsFile
	print("Searching for JS FIles")
	print("----------------------")
	command = "printf '"+ "\n".join(domains) +"' | subjs "  # => lists out all the JS files linked to the domains in the filename.txt
	JSFiles = os.popen(command).read()
	print(command)
	print(JSFiles)
	return(JSFiles.split())

#---------------------------------------------------------------------------------------


def checkSubTakeover(domains): #subzy
	print("Checking Subdomain Takeover")
	print("---------------------------")
	command = "subzy --target " + ",".join(domains)
	takeover = os.popen(command).read()
	# print(takeover)
	return(takeover)


#OK
def httprobe(domains):
	print("domainsList : ",domains)
	# domains is a list of domains and subdomains to be tested via httprobe 
	command = 'printf "' + "\n".join(domains) + '" | httprobe '
	command = "printf '{}' | httprobe ".format( escapeOSCI("\n".join(domains), ['\n']) )
	
	print(command)
	op = os.popen(command).read()
	# print(op.split())
	return(op.split())


# def takeSS(domains):
# 	print("Taking SS of websites")
# 	print("---------------------")
# 	command = "python3 webscreenshot.py -i " + httpDomainsFile + " -o " + fileloc + "images/"
# 	#input(command)
# 	os.chdir(basePath+"/webscreenshot")
# 	SS = os.popen(command).read()
# 	os.chdir(basePath)

#OK
def naabu(domains):
	print("Doing basic Port scan using Naabu")
	print("---------------------------------")
	scanResult = {}
	# file = open(file,"r")
	for domain in domains:
		print("\n",domain)
		domain = domain.strip("\n")
		command = "naabu -host " + domain 
		op = os.popen(command).read()
		scanResult[domain] = op.split()
		# input("python3 naabu output: \n"+op+"\n----------------------------")
		#command = "echo '-' >> " + fileloc + "portScan.txt"
		#op = os.popen(command).read()
		print("----------------------------------------------------")
	# file.close()
	return(scanResult)

#OK
def waybackurls(domain):
	print("Running WayBackUrls")
	print("-------------------")
	command = "printf " + domain + " | waybackurls "
	op = os.popen(command).read()
	# input("pytohn3 waybackurls output \n"+ op+ "\n-----------------------")
	# print(op)
	return(op.split())

#OK
def GHDB(domain):
	dorks = [
		'site:' + domain + ' ext:doc | ext:docx | ext:odt | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv  ',# publicly exposed Docs
		'site:' + domain + ' intitle:index.of  ',# Directory Listing
		'site:' + domain + ' ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini | ext:env ',# configuration files
		'site:' + domain + ' ext:sql | ext:dbf | ext:mdb ',# DB files
		'site:' + domain + ' ext:log ',# Log Files
		'site:' + domain + ' ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup ',# Backup and old files
		'site:' + domain + ' inurl:login | inurl:signin | intitle:Login | intitle:"sign in" | inurl:auth ',# Login Pages
		'site:' + domain + ' intext:"sql syntax near" | intext:"syntax error has occurred" | intext:"incorrect syntax near" | intext:"unexpected end of SQL command" | intext:"Warning: mysql_connect()" | intext:"Warning: mysql_query()" | intext:"Warning: pg_connect()" ',# SQL errors
		'site:' + domain + ' "PHP Parse error" | "PHP Warning" | "PHP Error" ',# PHP errors
		'site:' + domain + ' ext:php intitle:phpinfo "published by the PHP Group" ',# PHP info
		'site:github.com | site:gitlab.com "' + domain + '" ',# Github search
		'site:stackoverflow.com "' + domain + '" ',# StackOverflow search  
		'site:' + domain + ' inurl:signup | inurl:register | intitle:Signup ',# Signup Pages
	]
	# for i in dorks:
	# 	print(i)
	return(dorks)

def secretFinder(urls):
	print("Running SecretFinder")
	command = "python3 /home/neel/hacking/SecretFinder/SecretFinder.py -i {} -o cli"
	output = []
	dummy=[]
	for url in urls:
		op = os.popen(command.format(url)).read()
		# print(op)
		for string in op.split("\n"):
			if "->" in string:
				lhs,rhs = string.split("->")
				dummy.append(lhs.strip("\t") + " : " + rhs.strip("\t"))
			else:
				dummy.append(string)
		# output.append(op.split("\n"))
		output.append(dummy)
		dummy=[]
	return(output)


def escapeOSCI(string,extraAllowed=[]):
	print("in escapeOSCI")
	string = string.encode().decode("unicode-escape")
	# print(string)
	string = list(string)
	index=0
	length = len(string)
	lastStart = None
	newStr = []
	for char in string:
		if char not in extraAllowed:
			if char not in OSallowed:
				# newStr.append("\\")
				continue
		newStr.append(char)
	string = "".join(newStr)
	# print(string)
	return(string)