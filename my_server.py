# Abraham Gale 2020
# feel free to add functions to this part of the project, just make sure that the get_dns_response function works
from os import WIFSTOPPED
from resolver_backround import DnsResolver
import threading
import socket
import struct
import argparse
from sys import argv
from time import sleep
from helper_funcs import DNSQuery
from datetime import datetime, timedelta
from collections import defaultdict, OrderedDict

MAX_LEVEL = 10  # max number of iterative queries we make before we stop
CACHE_SIZE = 10000


class LRUCache:
    def __init__(self, Capacity):
        self.size = Capacity
        self.cache = OrderedDict()

    def get(self, key):
        if key not in self.cache:
            return None
        val = self.cache[key]
        self.cache.move_to_end(key)
        return val

    def put(self, key, val):
        with self.cache_lock:
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
        self.cache = LRUCache(CACHE_SIZE)

    def check_Cache(self, key, now):
        a = self.cache.get(key)
        if a:
            a = [record for record in a if record["expire_time"] > now]
            # Get rid of expire records
            self.cache.put(key, a if a else None)

    def query_then_cache(self, name_server, q):
        ### Regular Query
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("", 7000))
        sock.connect(
            (name_server, 53)
        )  # Dutch Dns Server that supports non recursive queries
        q.header["RD"] = 0  # we do not want recursive query
        sock.send(q.to_bytes())
        answer = sock.recv(512)
        a = DNSQuery(answer)
        # TODO Make this into a method so that we cache every time the resolver fetches during iterative query

        new_rr = defaultdict(list)
        for record in a.answers:
            # TODO if record["TYPE"] # Are certain types like SOA we don't cache
            key = (
                record["NAME"].decode("utf-8"),
                record["TYPE"],
                record["CLASS"],
            )
            val = {
                "expire_time": datetime.now() + timedelta(seconds=record["TTL"]),
                "resp": record,
            }
            new_rr[key].append(val)
        for key, val in new_rr.items():
            self.cache.put(key, val)
        print("%%")
        print([[str(num) for num in record["RDATA"]] for record in a.answers])
        print(a)
        return a
        # return a.to_bytes()

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

        def recursive_lookup(sname, stype, sclass, now=datetime.now()):
            if (
                datetime.now() - now > 100
            ):  # look up took longer than 100s we should return an error
                q.header["QR"] = 1
                q.header["RCODE"] = 2
                q.header["ANCOUNT"] = 0
                q.header["NSCOUNT"] = 0
                q.header["ARCOUNT"] = 0
                q.answers = []
                return q.to_bytes()

            key = (sname, stype, sclass)
            ### STEP 1 ###
            a = self.check_Cache(key, now)
            if a and any(True for record in a if record["expire_time"] > now):
                q.header["QR"] = 1
                q.header["ANCOUNT"] = len(a)
                q.header["AA"] = 0  # Because result is from a cache
                for record in a:
                    record["resp"]["TTL"] = int(
                        (record["expire_time"] - now).total_seconds()
                    )  # NOTE because "a" is a reference and not a copy so the cache object will change

                q.answers.extend([r["resp"] for r in a])
                return q.to_bytes()

            while True:

                ### STEP 2 ###
                sbelt = ["195.129.12.83", "199.9.14.201"]  # A and B root server
                slist = []
                while sname:
                    key = (sname, stype, sclass)
                    if a := self.check_Cache(key, now):
                        slist.append(a["RDATA"])  # put the ip address of the server
                slist.extend(sbelt)

                ### STEP 3 ###
                for server in slist:

                    ### STEP 4 ###
                    a = self.query_then_cache(server, q)

                    ### STEP 4.1 ###

                    if (a.answers and a.header["RCODE"] == 0) or a.header[
                        "RCODE"
                    ] == 3:  # TODO Maybe we need to check if domain name and type of answer section matches with original query
                        return a.to_bytes()

                    ### STEP 4.2 ###
                    elif a.answer and (
                        ns_rec := [rec for rec in a.answers if rec["TYPE"] == 2]
                    ):  # if there is an NS Record
                        break

                    ### STEP 4.3 ###
                    elif a.answers and (
                        cname_rec := [rec for rec in a.answers if rec["TYPE"] == 5]
                    ):  # if there is a CNAME Record
                        return recursive_lookup(
                            cname_rec[0]["RDATA"], stype, sclass, now
                        )

                    ### STEP 4.4 ###
                    # Go to the next server
                    # continue


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
