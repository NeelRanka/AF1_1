from ..server import app
from flask import jsonify,request
from .utility import *

@app.route("/subDomainTakeover",methods=["GET","POST"])
def checkSubTakeoverRoute(): #subzy
	domains = ['vupune.ac.in']
	#do error checking
	result = checkSubTakeover(domains)
	print("Subdomain Takeover : ",result)
	return(jsonify({"takeoverOutput":result}))
