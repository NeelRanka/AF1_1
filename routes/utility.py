import subprocess
#print(subprocess.check_output(['nslookup', 'google.com']))
import os
import sys

"""
try:
	domain = sys.argv[1]
	#print("domain : ",domain)
except:
	if len(sys.argv) < 2:
		print("No Domain Entered ")
		print("USAGE : python3 subEnum.py <domain>")
		exit(0)
	print(sys.argv)
	exit()

#check if valid domain

filepath = "/home/neel/hacking/Websites/"
dirname = domain.split(".")[0].lower()
filename =  dirname + ".txt"
httpDomainsFile=""


if not os.path.exists(filepath+dirname):
	os.mkdir(filepath+dirname)
	print(f"Created the directory {filepath+dirname}")
	fileloc = filepath+dirname+"/"   #shows the directory
	# print(fileloc)
else:
	fileloc = filepath+dirname+"/"
"""

basePath = "/home/neel/hacking"
# print(basePath)

def sublist3r():
	print("Running Sublist3r")
	print("-------------------")
	command = "python3 "+basePath+"/Sublist3r/sublist3r.py -d "+domain+" -o " + fileloc + filename 
	#sublist3r = os.popen(command).read()
	#print(sublist3r)


"""
def KnockPy():              ===> Needs to be processed IP + domains and all
	print("Running KnockPy")
	os.chdir(basePath+"/KnockPy")   #changing the current working directory

	#print(os.popen("ls").read())
	command = "python knock.py "+domain +" | tee -a "+basePath+"/"+fileloc+filename
	print(command)
	knockPy = os.popen(command).read()
	os.chdir(basePath)
"""


#OK
def subfinder(domain):
	# print("\n\nRunning Subfinder")
	# print("---------------------")
	command = "subfinder --silent -d "+ domain        #--silent flag to only show the subdomains as the output
	subfinder = os.popen(command).read()            # simply append the to the previous output, no processing required 
	# input("\npython3 subfinder output : \n"+subfinder+"\n-----------------------------------------")
	return(subfinder.split())

#OK
def assetfinder(domain):
	# print("\n\nRunning AssetFinder")
	# print("-----------------------")
	command = "assetfinder " + domain
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
	print(command)
	op = os.popen(command).read()
	# print(op.split())
	return(op.split())


def takeSS(domains):
	print("Taking SS of websites")
	print("---------------------")
	command = "python3 webscreenshot.py -i " + httpDomainsFile + " -o " + fileloc + "images/"
	#input(command)
	os.chdir(basePath+"/webscreenshot")
	SS = os.popen(command).read()
	os.chdir(basePath)

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



# sublist3r()
#KnockPy()
#subfinder()
#assetfinder()
#httpDomainsFile = findHttpDomains(fileloc+filename)  #returns the filename having only domains with http server running
#takeSS(fileloc+filename)
#findJSFiles()
#checkSubTakeover()
# naabu(["vupune.ac.in", "mescoepune.org"])
#waybackurls()

"""
def checkVirtualHosts(): #check for proper automation
	#check for virtual hosts and specifically the output
	#/home/neel/hacking/virtual-host-discovery/
	command = "ruby scan.rb --ip=<IP_Addr> --host=<domain/subdomain> | grep '(' "
	VHosts = os.popen(command).read()
	print(VHosts)
"""


# GHDB(domain)
