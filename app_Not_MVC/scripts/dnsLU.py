
import dns.resolver #Ce Package aide a iterroger les serveur DNS (DNS Louk Up)  


# Lobjet de cette classe peut rendre des infos DNS sur un domaine donne
class dnslu:
	valid=1
	site=0
	def __init__(self,dm):
		self.dm=dm
	def get_A(self):
		try:
			results_A=dns.resolver.resolve(self.dm,'A',search=True)
    		
		except(dns.exception.DNSException):
			self.valid=0
			results_A=['Invalid url'] #Attention EROR; str ne supporte pas la method .to_text()
		return(results_A)
    		
	def get_NS(self):
		try:
			return(dns.resolver.resolve(self.dm,'NS',search=True))
    		
		except(dns.exception.DNSException):
			site=1
			return(['-']) #Attention EROR; str ne supporte pas la method .to_text()

	def get_MX(self):
			try:
				return(dns.resolver.resolve(self.dm,'MX',search=True))
    		
			except(dns.exception.DNSException):
				return(['-']) #Attention EROR; str ne supporte pas la method .to_text()
