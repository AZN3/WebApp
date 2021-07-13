#! /usr/bin/python3

from scripts.dnsLU import dnslu
from scripts.RDAP import rdap
from scripts.shodanLU import shod
import requests

#cette classe gere le domaine entree. Elle contient des objet de type dnslu et rdaplu
class domain:
	dm='-'
	dnsRec='-' 
	ipAddr='-'
	shodRec='-'
	rdapRec='-' # c'est une liste si valid==1
	def __init__(self,dm):
		self.dm=dm
		self.dnsRec=dnslu(dm) #c'est un obket de type dnslu, on pet utiliser des methodes get_* pour recuperer des recordes du DNS
		self.rdapRec=rdap(self.dnsRec.get_A() , self.dnsRec.valid)
		self.shodRec=shod(self.dnsRec.get_A() , self.dnsRec.valid)
	#def get_rdap(self):
	#	rdapRec=rdap(self.dnsRec.get_A() ,self.dnsRec.valid)
	#	return(rdapRec)



	def get_subdomains(self):
		try:
			r = requests.get('https://crt.sh/?q='+self.dm+'&output=json')
			subs=[]
			for (key,value) in enumerate(r.json()):
				subs.append(value['name_value'])
		

			return(sorted(set(subs)))
		except Exception as e:
			return(['api error'])










