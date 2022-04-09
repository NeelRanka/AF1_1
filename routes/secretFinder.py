from ..server import app
from flask import jsonify,request
from .utility import *

"""
1. Take list of subdomains
2. pass them through httprobe
3. then use the printf "<httprobed urls>" | subjs

"""


@app.route("/secretFinder",methods=["GET","POST"])
def secretFinderRoute():
	print("in secretFinder")
	urls = ["http://vupune.ac.in","http://admin.volp.in"]
	#do error checking
	output = secretFinder(urls)
	# print("secretFinder : ",output)
	return(jsonify({"Files": output}))
