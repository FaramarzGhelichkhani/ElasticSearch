from config_elastic import connect
from Elasticsearch_Queries import *
import numpy as np

def Check_general_condition(asn,domain_list,app_list,time):
    elastic = connect()
    ip_list=[]
    fetch_data = elastic.search(index= 'iplytics_ipappdomain',body= General_condition_query(asn,domain_list,app_list,time))
    elastic.transport.close()
    distinct_ips = fetch_data['aggregations']['distinct ip']['buckets']
    for dict in distinct_ips:
        ip = dict['key']
        ip_list.append(ip)
    return  ip_list

def Check_dns_condition(ip_list,root_dns_list,time):
    elastic = connect()
    fetch_data = elastic.search(index= 'iplytics_dns-response',body= Dns_resolved_check_query(ip_list,root_dns_list,time))
    elastic.transport.close()
    result = []
    for dict in fetch_data['aggregations']['ip']['buckets']:
        ip = dict['key']
        dnsdist = {}
        for data in dict['dns']['buckets']:
            root_dns = ''.join(list(data['key'])[1:-1])
            number_of_sub_domain = data['sub']['value']
            percent = data['percent']['value']
            hit = data['total_hits']['value']
            dnsdist = {**dnsdist,root_dns:{ 'sub': number_of_sub_domain, 'percent': percent * 100, 'hit': hit}}
        result.append({"ip": ip, "dns_dist": dnsdist})
    return  result

def Check_aggregation_domain_app(ip_list, domain_list, app_list,time):
    result = []
    elastic = connect()
    fetch_data = elastic.search(index= 'iplytics_ipappdomain',body=Aggregation_ipappdoamin_query(ip_list, domain_list, app_list,time))
    elastic.transport.close()
    data = fetch_data['aggregations']['ips']['buckets']
    for dicts in data:
        ip = dicts['key']
        total_traffic   = dicts['total traffic']['value']
        total_hit       = dicts['total hit']['value']
        app_traffic     = dicts['app_traffic']['value']
        domain_traffic  = dicts['domain_traff']['value']
        result.append({'ip':ip,'app_traffic':app_traffic,'domain_traffic':domain_traffic,'total_hit':total_hit,'total_traffic':total_traffic})
    return result

def Check_aggregation_port(ip_list,port_list,time):
    result = []
    elastic = connect()
    fetch_data = elastic.search(index='iplytics_ip-port',body=Aggregation_ipport_query(ip_list,port_list,time))
    elastic.transport.close()
    data = fetch_data['aggregations']['ips']['buckets']
    for dicts in data:
        ip = dicts['key']
        port_traffic = dicts['port_traffic']['value']
        result.append({'ip': ip, 'port_traffic': port_traffic})
    return result

def Ip_finder(ip):
    asn                 = list(ip.asn)
    traffic             = ip.total_traffic
    hit                 = ip.totalhit
    time                = ip.time
    domain_list         = ip.domain_dist
    app_list            = ip.app_dist
    port_list           = ip.port_dist
    root_dns_list       = ip.dns_dist

    domainlist          = [domain.domain for domain in domain_list]
    domain_percentages  = np.array([domain.percent for domain in domain_list])

    appidlist           = [app.app_id for app in app_list]
    app_percentages     = np.array([app.percent for app in app_list])
    
    portlist            = [port.port for port in port_list]
    port_percentages    = np.array([port.percent for port in port_list])

    rootdnslist         = [dns.dns for dns in root_dns_list]
    dns_percentages     = np.array([dns.percent for dns in root_dns_list])
    dns_sub             = np.array([dns.sub for dns in root_dns_list])


    # check general conditions:
    ip_list = Check_general_condition(asn, domainlist, appidlist,time)
    print("number of ip  after general conditions  filter : ", len(ip_list))

    # check dns condition
    if len(rootdnslist) == 0:  # not dns to resolve
        dns_check_ips = [dict["ip"] for dict in Check_dns_condition(ip_list, rootdnslist,time)]
        ip_list = list(set(ip_list) - set(dns_check_ips))
        print("Not dns condition activated")
    elif len(rootdnslist) >= 1:
        dns_data = Check_dns_condition(ip_list, rootdnslist,time)
        ip_list = []
        fetchdnspercentage = []
        fetchdnssub = []
        for dict in dns_data:
            for index in range(len(rootdnslist)):
                key = rootdnslist[index]
                if key in dict['dns_dist']:
                    fetchdnspercentage.append(dict['dns_dist'][key]['percent'])
                    fetchdnssub.append(dict['dns_dist'][key]['sub'])
            try:
                if (np.array(fetchdnspercentage) >= np.array(dns_percentages)).all() and \
                        (np.array(fetchdnssub) >= np.array(dns_sub)).all():
                    ip_list.append(dict['ip'])
                fetchdnspercentage = []
                fetchdnssub = []
            except:
                fetchdnspercentage = []
                fetchdnssub = []

    print("number of ip  after  Dns filter : ", len(ip_list))

    # check app and domain disturbution
    app_domain_agg_data = Check_aggregation_domain_app(ip_list, domainlist, appidlist,time)
    ip_list = []
    for dict in app_domain_agg_data:
        app_ratio    = np.array(dict['app_traffic'])
        domain_ratio = np.array(dict['domain_traffic'])
        total_trafic = dict['total_traffic']
        total_hit = dict['total_hit']
        if ((app_ratio >= app_percentages).all() and (
                domain_ratio >= domain_percentages).all() and total_hit >= hit and total_trafic >= traffic):
            ip_list.append(dict['ip'])
    print("number of ip  after apps and domains traffic disturbutions filter : ", len(ip_list))

    # check port disturbution
    port_agg_data = Check_aggregation_port(ip_list, portlist,time)
    ip_list = []
    for dict in port_agg_data:
        port_ratio = np.array(dict['port_traffic'])
        if (port_ratio >= port_percentages).all():
            ip_list.append(dict['ip'])

    print("number of ip  after port disturbutions filter : ", len(ip_list))
    return ip_list
