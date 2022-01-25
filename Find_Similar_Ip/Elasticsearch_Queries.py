def General_condition_query(asn,domain_list,app_list,time):
	domain_condition =  " ".join("(*{}*)".format(domain) for domain in domain_list)
	query = {
  	"size": 0,
  	"query": {"bool": {"must": [
    	{"range": {"date": time}},
    	{"terms": { "geoasn.asn": asn}},
    	{"terms": {"app.app_id": app_list}},
    	{"query_string": {"query": domain_condition,"default_field": "domain_name.keyword"}},
    	]}},
    	"aggs": {"distinct ip": {"terms": {"field": "ip","size": 10000}}}
  
	}
	return query

def Dns_resolved_check_query(ip_list,root_dns_list, time):
    size  = len(ip_list)
    query = {
            "size": 0,
            "query": {"bool": {"must": [
            {"range": {"date": time}},
            {"terms": {"ip": ip_list }}
                                        ]}},
"aggs": {
            "ip": {
                "terms": {
                    "field": "ip",
                    "size": size
                }, "aggs": {
                    "dns": {
                        "terms": {
                            "field": "domain_name.keyword",
                            "size": 1000,
                            "script": {
                                "source": """
                    def a=doc['domain_name.keyword'].value;
                    def len=a.length();
                    def split_path=a.splitOnToken('.');
                    def rr=split_path.length;
                    def sw=split_path[rr-1];
                    def port=sw.indexOf(':'); 
                    def dns_list = [];
                    dns_list = {dns};
                    def result = [];
                    
                    if(port>0){{ len=port; sw=sw.substring(0,len) }} 
                    def final='';
                    final+=split_path[rr-2];
                    final+='.';
                    final+=sw; 
                    
                    for(int i=0;i<dns_list.size();i++){{ if(dns_list[i]==final) {{ result.add(final) }} }}
                    return result                    """.format(dns= root_dns_list)

                            }
                        },
                        "aggs": {
                            "sub": {
                                "cardinality": {
                                    "field": "domain_name.keyword"
                                }
                            },
                            "total_hits": {
                                "sum": {
                                    "field": "hits"

                                }

                            },
                            "percent": {
                                "normalize": {
                                    "buckets_path": "total_hits", "method": "percent_of_sum", "format": "00.00%"}

                            }
                        }
                    }
                }
            }
        }
    }
    return query

def Aggregation_ipappdoamin_query(ip_list, domain_list, app_list,time):
    size  = len(ip_list)
    query = {
        "size":0,
        "query": {
          "bool": {
            "must":
            [
               {"range": {"date": time}},
                {
                    "terms": {
		                        "ip": ip_list

		                    }}

            ]
         }
        },
        "aggs": {
            "ips": {
            "terms": {
                "field": "ip",
                "size": size

            },
            "aggs": {
                "total hit": {"sum": {"field": "hits"}},
                "total traffic": {"sum": {"field": "bsc", "script": "return doc['bcs'].value+doc['bsc'].value"}},
                "domain_traff":{
                  "scripted_metric": {
                    "init_script": {
                    "source": "state.doms = []; state.bsc = []; state.bcs=[]; ",
                    "lang": "painless"
                    },
                    "map_script": {
                    "source": "  state.doms.add(doc['domain_name.keyword'].value); state.bsc.add(doc.bsc.value); state.bcs.add(doc.bcs.value)",
                    "lang": "painless"
                    },
                    "combine_script": {
                    "source": "return state;",
                    "lang": "painless"
                    },
                    "reduce_script": {
                    "source": """  def r=0; def root_doms= []; def doms=[]; doms={};
                    def firstIndex=0;def result=[];def secondIndex=0;def g=0; def le=0; def s3;def
                     len2;def s;def port;def s2=[];def len;def org;  def path3=[];
                      def path4=[];  def dom_list=[]; def flag=true; def traff=[]; def total=0;
                    for(int i=0;i<doms.size();i++){{traff.add(0)}}
                    for(ss in states){{for(int j=0;j<ss.doms.size();j++){{
                        org=ss.doms[j];  len=org.length();  def concat='';def path=[];def path2=[]; total=total+ss.bcs[j]+ss.bsc[j];
                       for(int a=len;a>0;a--){{path.add(org.substring(a-1,a))}} firstIndex=path.indexOf('.'); 
                        s2=org.substring(firstIndex+1,len); le=s2.length(); for(int b=le;b>0;b--){{path2.add(org.substring(b-1,b));}} 
                        secondIndex=path2.indexOf('.'); g=firstIndex+secondIndex+1;  g=len-g; port=org.indexOf(':'); if(port>0){{len=port}} 
                        if(secondIndex==-1 || firstIndex==0){{g=0}} for(int b=g;b<len;b++){{ concat+=org.substring(b,b+1)}} 
                      for(int i=0;i<doms.size();i++){{if(doms[i]==concat){{traff[i]=traff[i]+ss.bcs[j]+ss.bsc[j]}}}}}}  }}
                    def traf =[];
                    for(int i=0; i<traff.size();i++){{traf.add(traff[i]*100.0/total)}}
                    return traf""".format(domain_list),
                    "lang": "painless"
                    }
               }},

                "app_traffic":{
                "scripted_metric": {
                    "init_script": {
                    "source": "state.ids = []; state.bsc = []; state.bcs=[]; ",
                    "lang": "painless"
                    },
                    "map_script": {
                    "source": "  state.ids.add(doc['app.app_id'].value); state.bsc.add(doc.bsc.value); state.bcs.add(doc.bcs.value)",
                    "lang": "painless"
                    },
                    "combine_script": {
                    "source": "return state;",
                    "lang": "painless"
                    },
                    "reduce_script": {
                    "source": """ def res = []; def a=[]; a={}; def r=0; def total=0;
                    for(int i=0;i<a.size();i++){{ for(s in states){{for(int j=0;j<s.ids.size();j++){{
                                if(s.ids[j]==a[i]){{r=r+s.bcs[j]+s.bsc[j]}} total=total+s.bcs[j]+s.bsc[j];
                    }}
                                }} res.add(r*100.0/total); r=0; total=0;
                            }}
                   
                    return res """.format(app_list),
                    "lang": "painless"
                    }
               }
             }
            }
         }
        }
     }

    return query

def Aggregation_ipport_query(ip_list,port_list,time):
	size = len(ip_list)
	query= {"size":0,
        "query": {
            "bool": {
            "must": 
            [
                {"range": {"date": time}},
                {
                "terms": {
		                        "ip": ip_list
                        
                            }
                }
                
            ]
            }
        },
        "aggs": {
            "ips": {
            "terms": {
                "field": "ip",
                "size": size
            },
            "aggs":{
            "port_traffic":{
                "scripted_metric": {


                    "init_script": {
                    "source": "state.port = []; state.traff = []; ",
                    "lang": "painless"
                    },
                    "map_script": {
                    "source": "  state.port.add(doc['port'].value); state.traff.add(doc.traffic.value); ",
                    "lang": "painless"
                    },
                    "combine_script": {
                    "source": "return state;",
                    "lang": "painless"
                    },
                    "reduce_script": {
                    "source": """ def res = []; def a=[]; def b=0; a={port_list}; def r=0;
                    for(int i=0;i<a.size();i++){{ for(s in states){{for(int j=0;j<s.port.size();j++){{
                                if(s.port[j]==a[i]){{r=r+s.traff[j]}}b=b+s.traff[j];
                    }}
                                }}  res.add(r*100.0/b);b=0; r=0;
                            }}
                    
                    return res """.format(port_list=port_list),
                    "lang": "painless"
                    } 
                }

              }
            }
          }
        }
    }
	return query