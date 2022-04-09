from ..server import app
from flask import jsonify,request
from .utility import *

@app.route("/portScan",methods=["GET","POST"])
def naabuRoute():
	domains = ["vupune.ac.in"]
	print("in PortScan")
	#do error checking
	if "domains" in request.form:
		print("request form : ",request.form['domains'])
		domains = request.form['domains']
	if "domains" in request.json:
		print("request JSON : ",request.json['domains'])
		domains = request.json['domains']
	if type(domains) != list:
		return("Jhool hua hai!! No list found")
	portScanResult = naabu(domains)
	print("Port Scan : ",portScanResult)
	return(portScanResult)
