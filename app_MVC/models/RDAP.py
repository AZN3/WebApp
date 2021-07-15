


from ipwhois import IPWhois

class rdap:

	#data_rdap=[]

	def __init__(self,ip,valid):
		self.ip=ip
		self.valid=valid
		if valid:
			self.data=IPWhois(ip[0]).lookup_rdap()
		else:
			data_rdap=[{'etat':'Invalide!!'}]	# a correge

	def get_rdap(self):
		data_rdap=[]

		net_list=list(self.data['network'].keys())

		data_rdap.append({'query' :  self.data['query']})
		data_rdap.append({'asn' :  self.data['asn']})
		data_rdap.append({'asn_cidr' :  self.data['asn_cidr']})
		data_rdap.append({'asn_country_code' :  self.data['asn_country_code']})
		data_rdap.append({'asn_date' :  self.data['asn_date']})
		data_rdap.append({'asn_registry' :  self.data['asn_registry']})
		data_rdap.append({'asn_description' :  self.data['asn_description']})
		data_rdap.append({'entities' :  self.data['entities']})

		net=[]
		for e in net_list:
			if type(self.data['network'][e]) is str:
				net.append( {e : self.data['network'][e]} )

		data_rdap.append({'network' :  net })
		objs=[]
		for ob in list(self.data['objects'].keys()):
			obj=[{'handle':self.data['objects'][ob]['handle']} , {'status':self.data['objects'][ob]['status']}]
			cont={}


			cont['role']=self.data['objects'][ob]['contact']['role']
			cont['title']=self.data['objects'][ob]['contact']['title']

			for elem in list(self.data['objects'][ob]['contact'].keys()):
				if elem in ('phone' , 'address','email'):
					if self.data['objects'][ob]['contact'][elem] != None:
						cont[elem]= self.data['objects'][ob]['contact'][elem]
					else:
						cont[elem] = '-'

			obj.append({'contact':cont})
			objs.append(obj)







		data_rdap.append({'objects': objs})


		return(data_rdap)

