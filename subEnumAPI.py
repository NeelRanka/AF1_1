import subprocess
import os
import sys
import uuid
from flask import make_response,jsonify
from zipfile import ZipFile


def initialize(domain):
	filepath = os.path.join( os.getcwd(), "Websites/" ) 
	dirname = domain.split(".")[0].lower()
	filename =  dirname + ".txt"
	httpDomainsFile=""
	if not os.path.exists(filepath+dirname):
		os.mkdir(filepath+dirname)
		print(f"Created the directory {filepath+dirname}")
		fileloc = filepath+dirname+"/"   #shows the directory
		print(fileloc)
	else:
		fileloc = filepath+dirname+"/"
	return(fileloc)

"""
def sublist3r():
	print("Running Sublist3r")
	print("-------------------")
	command = "python3 "+basePath+"/Sublist3r/sublist3r.py -d "+domain+" -o " + fileloc + filename 
	sublist3r = os.popen(command).read()
	print(sublist3r)


def KnockPy():              ===> Needs to be processed IP + domains and all
	print("Running KnockPy")
	os.chdir(basePath+"/KnockPy")   #changing the current working directory

	#print(os.popen("ls").read())
	command = "python knock.py "+domain +" | tee -a "+basePath+"/"+fileloc+filename
	print(command)
	knockPy = os.popen(command).read()
	os.chdir(basePath)
"""

"""
def checkVirtualHosts(): #check for proper automation
	#check for virtual hosts and specifically the output
	#/home/neel/hacking/virtual-host-discovery/
	command = "ruby scan.rb --ip=<IP_Addr> --host=<domain/subdomain> | grep '(' "
	VHosts = os.popen(command).read()
	print(VHosts)
"""

def subfinder(domain):
	print("\n\nRunning Subfinder")
	print("---------------------")
	command = "subfinder --silent -d "+ domain + " | anew " + fileloc + "subDomains.txt"       #--silent flag to only show the subdomains as the output
	subfinder = os.popen(command).read()            # simply append the to the previous output, no processing required 
	print(subfinder)


def assetfinder(domain):
	print("\n\nRunning AssetFinder")
	print("-----------------------")
	command = "assetfinder " + domain + " | anew " + fileloc + "subDomains.txt"
	assetfinder = os.popen(command).read()          # simply append the to the previous output, no processing required
	print(assetfinder)


# now get the subdomains approved by the user
# and use those for further processing

#-----------------------------------------------------------------------------------

def findHttpDomains(fileloc,subDomainFilename):
	# global fileloc
	#print("in httpDomains")
	httpDomainsFile = fileloc + "httpDomains.txt"
	command = "cat " + fileloc + subDomainFilename + " | grep "+ domain +" | httprobe | anew " + httpDomainsFile
	print(command)
	os.popen(command).read()
	print("HttProbed and created the file :" , httpDomainsFile)
	return(httpDomainsFile)

#---------------------------------------------------------------------------------------



def findJSFiles(httpDomainsFile,basePath):  #fileloc is the baseDir
	# global httpDomainsFile
	print("Searching for JS FIles")
	print("----------------------")
	command = "cat "+ httpDomainsFile +" | subjs | anew " + basePath + "JSfiles.txt"  # => lists out all the JS files linked to the domains in the filename.txt
	JSFiles = os.popen(command).read()
	print("now you can search manually/via a program for the JS files listed in the "+basePath+"JSfiles.txt file")


#---------------------------------------------------------------------------------------


def checkSubTakeover(httpDomainsFile,basePath): #subzy
	print("Checking Subdomain Takeover")
	print("---------------------------")
	command = "subzy --targets " + httpDomainsFile + " > " + basePath + "/subDomainTakeover.txt"
	takeover = os.popen(command).read()
	print(takeover)


#----------------------------------------------------------------------------------------


# def takeSS(httpDomainsFile,basePath):
# 	print("Taking SS of websites")
# 	print("---------------------")
# 	baseDir = os.getcwd()
# 	# print(baseDir)
# 	command = "python3 " + baseDir +"/tools/webscreenshot/webscreenshot.py -i " + httpDomainsFile + " -o " + basePath + "images/"
# 	#input(command)
# 	SS = os.popen(command).read()
	
#----------------------------------------------------------------------------------------

def naabu(subDomainsFile,domain,basePath):
	print("Doing basic Port scan using Naabu")
	print("---------------------------------")
	file = open(subDomainsFile,"r")
	for currDomain in file:
		if domain not in currDomain:
			continue
		print("\n",currDomain)
		currDomain = currDomain.strip("\n")
		command = "naabu -host " + currDomain + " >> " + basePath + "portScan.txt"
		op = os.popen(command).read()
		command = "echo '-' >> " + basePath + "portScan.txt"
		op = os.popen(command).read()
		print("----------------------------------------------------")
	file.close()

#---------------------------------------------------------------------------------------

def waybackurls(domain,basePath):
	print("Running WayBackUrls")
	print("-------------------")
	command = "printf " + domain + " | waybackurls > " + basePath + "waybackurls.txt"
	print(command)
	op = os.popen(command).read()


def findSubdomains(domain):
	#have written to the file subDomains.txt
	subfinder(domain)
	assetfinder(domain)
	# return the contents of the file fileloc+"subDomains.txt"
	with open(fileloc+"subDomains.txt") as f:
		subdomains = f.read().split("\n")
	return(subdomains)

def detectWAF(httpDomainsFile,basePath):
	print("detecting WAF using wafw00f")
	command = "wafw00f -i '{}' -o '{}wafDetails.txt' ".format(httpDomainsFile,basePath)
	# command = "wafw00f -i " + httpDomains + " -o " + basePath + "wafDetails.txt"
	print(command)
	op = os.popen(command).read()


def filterWayback(basePath,filename):
	print("making filtered outputs of waybackURLS")
	command = "bash ./Tools/waybackFilter.sh '{}' '{}'".format(basePath,filename)
	print(command)
	op = os.popen(command).read()


#
def SecretFinder(basePath,filename):
	print("Running Secret Finder on JS Files")
	JSfiles = open(basePath+filename).read().split("\n")
	mainCommand = "python3 ./Tools/SecretFinder/SecretFinder.py -i '{}' -o cli >> '{}JSFinder.txt'"
	for url in JSfiles:
		if url != "" :
			command = mainCommand.format(url,basePath)
			print(command)
			op = os.popen(command).read()



#store the domains to be further processed in a file and pass that file path to findHttpDomains
def completeProcess(domain=None,todo=None,subDomains=None,httpDomains=None):
	basePath = initialize(domain)
	if domain!=None:
		if "wayBackUrls" in todo:
			waybackurls(domain,basePath)
			filterWayback(basePath,"waybackurls.txt")
		#perform GF-patterns on waybackURLS output

	if todo != None:
		if subDomains != None:
			subDomainsFile = createFile(subDomains,basePath,"subDomains.txt")
			if "portScan" in todo:
				naabu(subDomainsFile,domain,basePath)
	
		if httpDomains!=None:
			httpDomainsFile = createFile(httpDomains,basePath,"httpDomains.txt")  #returns the filename having only domains with http server running
			if "JSFiles" in todo:
				findJSFiles(httpDomainsFile,basePath)
				SecretFinder(basePath,"JSfiles.txt")
			if "subTakeover" in todo:
				checkSubTakeover(httpDomainsFile,basePath)
			if "wafDetect" in todo:
				print("trying WAF detection")
				detectWAF(httpDomainsFile,basePath)
	
	#now zip the particular folder and send it to the user
	zipFolder(basePath,domain)



def getAllPaths(basePath):
	file_paths = []
  
	# crawling through directory and subdirectories
	for root, directories, files in os.walk(basePath):
		for filename in files:
			filepath = os.path.join(root, filename)
			file_paths.append(filepath)
  
	return file_paths


def zipFolder(basePath,domain):
	file_paths = getAllPaths(basePath)
	length = len(basePath)
	with ZipFile(basePath + domain.split(".")[0].lower() + ".zip",'w') as zip:
		# writing each file one by one
		for file in file_paths:
			filename = file[length:]
			zip.write(file,filename)


def createFile(listOfString,basePath,filename):
	print("creating file",basePath+filename)
	file = open(basePath+filename,"w")
	file.write("\n".join(listOfString))
	file.close()
	return(basePath+filename)




def returnResponse(code, msg, data=""):
	if len(data)!=0:
		return( make_response( jsonify({ "code": code, "msg": msg, "data": data }), code ) )
	return( make_response( jsonify({ "code": code, "msg": msg }), code ) )	
