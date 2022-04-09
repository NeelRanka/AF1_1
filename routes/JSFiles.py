from ..server import app
from flask import jsonify,request
from .utility import *

"""
1. Take list of subdomains
2. pass them through httprobe
3. then use the printf "<httprobed urls>" | subjs

"""


@app.route("/JSFiles",methods=["GET","POST"])
def findJSFilesRoute():
	domains = ["http://vupune.ac.in"]
	print("in JSFiles")
	print(request.form)
	print(request.json)
	if "domains" in request.form:
		print("request form : ",request.form['domains'])
		domains = request.form['domains']
	if "domains" in request.json:
		print("request JSON : ",request.json['domains'])
		domains = request.json['domains']
	if type(domains) != list:
		return("Jhool hua hai!! No list found")
	#do error checking
	files = findJSFiles(domains)
	print("JSFiles: ",files)
	return(jsonify({"Files":files}))