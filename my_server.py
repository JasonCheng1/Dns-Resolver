#Abraham Gale 2020
#feel free to add functions to this part of the project, just make sure that the get_dns_response function works
from resolver_backround import DnsResolver
import threading
import socket
import struct
import argparse
from sys import argv
from time import sleep
from helper_funcs import DNSQuery
class MyResolver(DnsResolver):
        def __init__(self, port):
                self.port = port
                #define variables and locks you will need here
                self.cache_lock = threading.Lock()
        def get_dns_response(self, query):
                #input: A query and any state in self
                #returns: the correct response to the query obtained by asking DNS name servers
                #Your code goes here, when you change any 'self' variables make sure to use a lock
                print('***')
                print(query)
                print('&&&')
                q = DNSQuery(query)
                print(q)
                print(q.to_bytes())
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind(('', 7000))
                sock.connect(('8.8.8.8', 53))
                sock.send(q.to_bytes())
                answer = sock.recv(512)
                a = DNSQuery(answer)
                print('%%')
                print([[str(num) for num in record['RDATA']] for record in a.answers])
                print(a)
                #temp = a.answers[0]
                #a.answers[0] = a.answers[1]
                #a.answers[1] = temp
                print(a.to_bytes())
                return a.to_bytes()
parser = argparse.ArgumentParser(description="""This is a DNS resolver""")
parser.add_argument('port', type=int, help='This is the port to connect to the resolver on',action='store')
args = parser.parse_args(argv[1:])
resolver = MyResolver(args.port)
resolver.wait_for_requests()
