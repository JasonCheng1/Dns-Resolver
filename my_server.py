# Abraham Gale 2020
# feel free to add functions to this part of the project, just make sure that the get_dns_response function works
from resolver_backround import DnsResolver
import threading
import socket
import struct
import argparse
from sys import argv
from time import sleep
from helper_funcs import DNSQuery

MAX_LEVEL = 10 # max number of iterative queries we make before we stop

class MyResolver(DnsResolver):
    def __init__(self, port):
        self.port = port
        # define variables and locks you will need here
        self.cache_lock = threading.Lock()

    def get_dns_response(self, query):
        # input: A query and any state in self
        # returns: the correct response to the query obtained by asking DNS name servers
        # Your code goes here, when you change any 'self' variables make sure to use a lock
        print("***")
        print(query)
        print("&&&")
        q = DNSQuery(query)
        print(q)
        # print(q.to_bytes())

        ### Reject EDNS
        if q.header["ARCOUNT"] and any(rec["TYPE"] == 41 for rec in q.answers):
            ### EDNS
            # Reference: https://tools.ietf.org/html/rfc6891#section-6
            q.header["QR"] = 1
            q.header["RCODE"] = 2  # /3/4 Not sure if this is the right one or is this the only thing I need to do
            q.header["ANCOUNT"] = 0
            q.header["NSCOUNT"] = 0
            q.header["ARCOUNT"] = 0
            q.answers = []
            return q.to_bytes()

        """
        ### PseudoCode ###
        # DNS Functions: https://tools.ietf.org/html/rfc1034#section-5.2.1
        # host name -> host address  <- implementing this one
        # host address -> host name (inverse query)
        # general lookup 

        # Algo: https://tools.ietf.org/html/rfc1034#section-4.3.2
        sname, stype, sclass = q.question["NAME"], q.header["QTYPE"], q.header["QCLASS"]
        slist = []
        sbelt = [] # initialize this using a configuration file use a couple of the root servres
        # q.header["RD"] = 0 #no recursive queries
        ns = "198.41.0.4" # #13 root servers https://www.internic.net/domain/named.root
        
        if (sname, stype, sclass) in self.cache_lock and not expired:
            return "we have our answer put into a dns response"

        # www.google.com. -> google.com. -> com. -> ""
        while qname:
            if (sname, stype, sclass) in self.cache_lock and not expired:
                    slist.append(self.cache_lock[(sname, stype, sclass)]["ns"])
            qname = qname[qname.find(".")+1:] 
            slist.reverse()
            #slist is now in the form of wrose -> best
        

        def recursive_lookup(qname: str,  ns: str, qtype: str = "A",  qclass: str = "1"): 
            while True:
                server = (ns, 53)
                resp = self.lookup(qname, server) #create socket -> send dns query with qname in question
                if resp.answers and resp.header["RCODE"] == 0: # 0 = NOERROR:

                    return resp #we got the ans
                
                if resp.header["RCODE"] == 3: # 3 = NXDOMAIN
                    return resp #qname DNE

                if new_ns = resp.

        for ns in slist:
            recursive_lookup(...)

        #if slist is null or we can't find ans yet
        for ns in sbelt:
            recursive_lookup(...)
        """
        ### Regular Query
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("", 7000))
        sock.connect(("8.8.8.8", 53))
        sock.send(q.to_bytes())
        answer = sock.recv(512)
        a = DNSQuery(answer)
        print("%%")
        print([[str(num) for num in record["RDATA"]] for record in a.answers])
        print(a)
        # print(a.to_bytes())
        return a.to_bytes()

	def lookup(self, qname: str, ns):
        """
        setups and sends a dns query to a name server 

        returns query
        """
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((ns, 7000))
        sock.connect((, 53))
        sock.send(q.to_bytes())
        answer = sock.recv(512)
        a = DNSQuery(answer)
        print("%%")
        print([[str(num) for num in record["RDATA"]] for record in a.answers])
        print(a)
        # print(a.to_bytes())
        return a.to_bytes()
		

parser = argparse.ArgumentParser(description="""This is a DNS resolver""")
parser.add_argument(
    "port",
    type=int,
    help="This is the port to connect to the resolver on",
    action="store",
)
args = parser.parse_args(argv[1:])
resolver = MyResolver(args.port)
resolver.wait_for_requests()



