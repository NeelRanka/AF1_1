from ..server import app
from flask import jsonify,request
from .utility import *


@app.route("/findSubDomains",methods=['GET','POST'])
def findSubDomains():
	if request.method == "GET":
		return("OK")
	domain = "vupune.ac.in"
	domain = request.json['domain']
	print("received subdomains request for ",domain)
	#do error checking
	subdomains = []
	subdomains.extend(subfinder(domain))
	subdomains.extend(assetfinder(domain))
	# print(subdomains)
	subdomains = list(set(subdomains))
	checked,unchecked = findRelevantSubdomains(subdomains,domain)
	print("Subdomains : checked : ",checked,"\nUnchecked : ",unchecked)
	return(jsonify({ "checked":checked , "unchecked": unchecked}))
