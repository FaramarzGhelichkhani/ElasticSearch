from elasticsearch import RequestsHttpConnection
from elasticsearch import Elasticsearch

class MyConnection(RequestsHttpConnection):
	def __init__(self, *args, **kwargs):
		proxies = kwargs.pop('proxies', {})
		super(MyConnection, self).__init__(*args, **kwargs)
		self.session.proxies = proxies

def connect():
    hosts=""
    es = Elasticsearch(hosts=hosts,verify_certs=False,connection_class=MyConnection,proxies={'https':'http:172.30.112.9:6060'},timeout=600)
    es.cluster.health(wait_for_status='yellow', request_timeout=600)
    return es
