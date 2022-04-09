from ..server import app
from flask import jsonify,render_template,request,redirect
import os
from .utility import *

basePath = "/home/neel/hacking"
#app.route("/takeSS",methods=["GET"])
def takeSSRoute(file):
	print("Taking SS of websites")
	print("---------------------")
	command = "python3 webscreenshot.py -i " + httpDomainsFile + " -o " + fileloc + "images/"
	#input(command)
	os.chdir(basePath+"/webscreenshot")
	SS = os.popen(command).read()
	os.chdir(basePath)
