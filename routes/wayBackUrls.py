from ..server import app
from flask import jsonify,request
from .utility import *


@app.route("/wayBackUrls",methods=["GET","POST"])
def waybackurlsRoute():
	domain = "vupune.ac.in"
	if "domain" in request.form:
		print("request form : ",request.form['domain'])
		domain = request.form['domain']
	if "domain" in request.json:
		print("request JSON : ",request.json['domain'])
		domain = request.json['domain']
	if type(domain) != str:
		return("Jhool hua hai!! No string found")
	result = waybackurls(domain)
	print("waybackUrls : ",result)
	return(jsonify({"urls":result}))
