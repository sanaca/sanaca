import os,re,sys
import yaml
#we need apt-get install python-yaml for this to work !
#it is best if you set up suricata.yaml with EXTERNAL_NET: "any" !!
#
# This code is published under GPL v2 License Terms
#
# Descrpition: General Purpose rule parser
#
# Author: Peter Manev
# 11/11/2012


class SuriConf:
	
	def __init__(self, file=None):
		self.conf  = file
		self.vars  = {}
		self.src   = None
		self.dst   = None
		self.sport = None
		self.dport = None

	def default(self, extNet, homeNet):
		#self.vars = {
		#		"HOME_NET": homeNet,
		#		"EXTERNAL_NET": extNet,
		#		"DNS_SERVERS": homeNet,
		#		"SMTP_SERVERS": homeNet,
		#		"HTTP_SERVERS": homeNet,
		#		"SQL_SERVERS": homeNet,
		#		"TELNET_SERVERS": homeNet,
		#		"FTP_SERVERS": homeNet,
		#		"SNMP_SERVERS": homeNet,
		#		"HTTP_PORTS": 80,
		#		"SSH_PORTS": 22,
		#		"SHELLCODE_PORTS": 81,
		#		"ORACLE_PORTS": 1521,
		#		"FTP_PORTS": 21
		#	    }
		if not os.path.exists("Parser/default.conf"):
			print "Default config missing"
			sys.exit(1)

		f = open("Parser/default.conf",'r')
		conf = f.read().splitlines()
		for line in conf:
			name,data  = line.split(" ")
			if data == "HOME_NET": data = homeNet
			elif data == "EXTERNAL_NET": data = extNet
			self.vars[name] = data

		return self.vars
		
	def parse(self):
		f = open(self.conf, 'r')
		dataMap = yaml.load(f)
		f.close()
		
		for i in  dataMap["vars"]["port-groups"]:
		  data = dataMap["vars"]["port-groups"][i]
		  var  = i
		  if str(data).startswith("!$"):
			data = self.vars[data[2:]]
		  elif str(data).startswith("!"):
			data = int(data[1:]) + 1
		  elif str(data).startswith("$"):
			data = self.vars[data[1:]]
					
		  self.vars[var] = data
				
		for i in  dataMap["vars"]["address-groups"]:
		  data = dataMap["vars"]["address-groups"][i]
		  var  = i
		  
		  self.vars[var] = data
		  
		return self.vars 
		
