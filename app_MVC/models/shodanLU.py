

import shodan
class shod:
	SHODAN_API_KEY = 'oi7NggwAcQqjQ2dAExwtXc3l5gq0KmQN'
	def __init__(self,ip,valid):
		self.valid=valid
		if valid:
			try:

				self.shodanRec=shodan.Shodan(self.SHODAN_API_KEY).host(ip[0].to_text())
			except Exception as e:
				self.shodanRec={'etat':e}

		else:
			self.shodanRec={'etat':'Invalid URL!!'}


	def get_shod(self):
		data=[]
		if self.valid:
			k=list(self.shodanRec.keys())
			for key in k:
				if key == 'data':
					try:
						data.append({'Technologies': self.shodanRec['data'][0]['cpe']})
					except Exception as e:
						data.append({'Technologies':'-'})
				else:
					data.append({key:self.shodanRec[key]})
			try:
					vulns=self.shodanRec['vulns']

			except Exception as e:
					data.append({'vulns':['-']})
					vulns=['-']


			return(data,vulns)
		else:
			return([{'etat':'Invalid URL!!'}])
