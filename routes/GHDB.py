from ..server import app
from flask import jsonify,request
from .utility import *

app.route("/GHDB",methods=["GET"])
def GHDBRoute():
	#fetch domain from user data
	#do error checking
	domain = "vupune.ac.in"
	return(GHDB(domain))
