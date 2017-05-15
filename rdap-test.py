from ipwhois import IPWhois
from pprint import pprint

try:
    obj = IPWhois('2002::')
    results = obj.lookup_rdap(depth=1)
    #print (results['asn'])
    pprint(results)
except:
    print("somthing goes wrong")