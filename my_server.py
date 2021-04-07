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
from datetime import datetime, timedelta
from collections import OrderedDict

MAX_LEVEL = 10  # max number of iterative queries we make before we stop
CACHE_SIZE = 10000


class LRUCache:
    def __init__(self, Capacity):
        self.size = Capacity
        self.cache = OrderedDict()

    def get(self, key):
        if key not in self.cache:
            return -1
        val = self.cache[key]
        self.cache.move_to_end(key)
        return val

    def put(self, key, val):
        if key in self.cache:
            del self.cache[key]
        self.cache[key] = val
        if len(self.cache) > self.size:
            self.cache.popitem(last=False)


class MyResolver(DnsResolver):
    def __init__(self, port):
        self.port = port
        # define variables and locks you will need here
        self.cache_lock = threading.Lock()
        self.cache = (
            {}
        )  # TODO Not sure if there is a size limit on this if so then what process do I use to remove items in cache
        # self.cache = LRUCache(CACHE_SIZE)

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
            q.header["RCODE"] = 4
            q.header["ANCOUNT"] = 0
            q.header["NSCOUNT"] = 0
            q.header["ARCOUNT"] = 0
            q.answers = []
            return q.to_bytes()

        sname, stype, sclass = (
            q.question["NAME"].decode("utf-8"),
            q.question["QTYPE"],
            q.question["QCLASS"],
        )
        key = (sname, stype, sclass)
        now = datetime.now()
        if key in self.cache and self.cache[key]["expire_time"] > now:
            q.header["QR"] = 1
            q.header["ANCOUNT"] = 1
            q.header["AA"] = 0  # Because result is from a cache
            # a = self.cache.get(key)  # ["resp"]
            a = self.cache[key]["resp"]

            a["TTL"] = int(
                (self.cache[key]["expire_time"] - now).total_seconds()
            )  # NOTE because "a" is a reference and not a copy so the cache object will change
            q.answers.append(a)
            return q.to_bytes()

        else:
            ### Regular Query
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("", 7000))
            sock.connect(("8.8.8.8", 53))
            sock.send(q.to_bytes())
            answer = sock.recv(512)
            a = DNSQuery(answer)
            # TODO Make this into a method so that we cache every time the resolver fetches during iterative query
            for record in a.answers:
                # if record["TYPE"]
                key = (record["NAME"].decode("utf-8"), record["TYPE"], record["CLASS"])
                with self.cache_lock:
                    self.cache[key] = {
                        "insert_time": datetime.now(),
                        "expire_time": datetime.now()
                        + timedelta(seconds=record["TTL"]),
                        "resp": record,
                    }
            print("%%")
            print([[str(num) for num in record["RDATA"]] for record in a.answers])
            print(a)
            # print(a.to_bytes())
            return a.to_bytes()


# def lookup(self, qname: str, ns):
#     """
#     setups and sends a dns query to a name server

#     returns query
#     """
# 	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#     sock.bind((ns, 7000))
#     sock.connect((, 53))
#     sock.send(q.to_bytes())
#     answer = sock.recv(512)
#     a = DNSQuery(answer)
#     print("%%")
#     print([[str(num) for num in record["RDATA"]] for record in a.answers])
#     print(a)
#     # print(a.to_bytes())
#     return a.to_bytes()


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

