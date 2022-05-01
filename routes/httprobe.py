from ..server import app
from flask import jsonify,request
from .utility import *


@app.route("/httprobe",methods=["GET","POST"])
def httprobeRoute():
	if request.json:
		if "domains" in request.json:
			domains = request.json['domains']
		else:
			return(jsonify({"code":404, "msg": "no domain given"}))
	else:
		return ( jsonify({"code":404, "msg":"no json data passed"}) )
	# domain = escapeOSCI(domain)
	result = httprobe(domains)
	print("httprobe : ",result)
	return(jsonify({"urls":result}))