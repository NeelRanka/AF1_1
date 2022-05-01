from ..server import app
from flask import jsonify,request
from .utility import *


@app.route("/findSubDomains",methods=['GET','POST'])
def findSubDomains():
	if request.method == "GET":
		return("OK")
	if request.json:
		if "domain" in request.json:
			domain = request.json['domain']
		else:
			return(jsonify({"code":404, "msg": "no domain given"}))
	else:
		return ( jsonify({"code":404, "msg":"no json data passed"}) )
	domain = escapeOSCI(domain)
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
