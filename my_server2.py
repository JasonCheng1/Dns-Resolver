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
import copy
import random
import ipaddress

MAX_LEVEL = 10  # max number of iterative queries we make before we stop
CACHE_SIZE = 100000

# TYPE Values
A_TYPE = 1
NS_TYPE = 2
CNAME_TYPE = 5

NOERROR_RCODE = 0
NAMEERROR_RCODE = 3


class LRUCache:
    def __init__(self, Capacity):
        self.size = Capacity
        self.cache_lock = threading.Lock()
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
        self.cache = LRUCache(CACHE_SIZE)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("", 7000))

    def check_Cache(self, key, now):
        a = self.cache.get(key)
        if a:
            a = [record for record in a if record["expire_time"] > now]  # Get rid of expired records
            self.cache.put(key, a if a else None)
            return list(map(lambda rec: rec["resp"], a))
        return None

    def check_Cache_ret_time(self, key, now):
        a = self.cache.get(key)
        if a:
            a = [record for record in a if record["expire_time"] > now]  # Get rid of expired records
            self.cache.put(key, a if a else None)
            return a
        return None

    def query_then_cache(self, name_server, q):
        name_server = str(ipaddress.ip_address(name_server))
        print("WHAT IS THE IP OF", q.question["NAME"], name_server)
        try:  # NOTE For some NS it wouldn't let me connect
            self.sock.connect((name_server, 53))
        except:
            print("Could not connect to", name_server)
            return q  # NOTE Something with no answers inside of it

        q.header["RD"] = 0  # we do not want recursive query
        self.sock.sendall(q.to_bytes())
        answer = self.sock.recv(512)
        a = DNSQuery(answer)

        if a.header["RCODE"] == NOERROR_RCODE:
            new_rr = defaultdict(list)
            for record in a.answers:
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
                # print("[CACHE]", key, val)
                self.cache.put(key, val)
        print("%%")
        # print([[str(num) for num in record["RDATA"]] for record in a.answers])
        print(a)
        return a

    def get_dns_response(self, query):
        # input: A query and any state in self
        # returns: the correct response to the query obtained by asking DNS name servers
        # Your code goes here, when you change any 'self' variables make sure to use a lock
        print("***")
        print(query)
        print("&&&")
        q = DNSQuery(query)
        print(q)

        ### Reject EDNS Reference: https://tools.ietf.org/html/rfc6891#section-6
        if q.header["ARCOUNT"] and any(rec["TYPE"] == 41 for rec in q.answers):
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
        # return self.recursive_lookup(q, sname, stype, sclass)
        return self.recursive_lookup2(q, sname, stype, sclass).to_bytes()

    def recursive_lookup2(self, q, sname, stype, sclass, now=datetime.now(), limit=180):
        if (datetime.now() - now) > timedelta(seconds=limit):  # look up took longer than 100s
            q.header["QR"] = 1
            q.header["RCODE"] = 2
            q.header["ANCOUNT"] = 0
            q.header["NSCOUNT"] = 0
            q.header["ARCOUNT"] = 0
            q.answers = []
            return q

        key = (sname, stype, sclass)
        ### STEP 1 ###
        a = self.check_Cache_ret_time(key, now)
        if a:
            q.header["QR"] = 1
            q.header["ANCOUNT"] = len(a)
            q.header["AA"] = 0  # Because result is from a cache
            for record in a:
                record["resp"]["TTL"] = int((record["expire_time"] - now).total_seconds())
            q.answers = [rec["resp"] for rec in a]
            # print(q)
            return q

        while True:
            ### STEP 2 ###
            sbelt = [
                "198.41.0.4",
                "195.129.12.83",
                "199.9.14.201",
            ]  # A and B root server
            slist = []
            split_sname = sname.split(".")
            for i in range(len(split_sname)):
                reduced_sname = ".".join(split_sname[i:])
                reduced_key = (reduced_sname, NS_TYPE, sclass)
                ns_records = self.check_Cache(reduced_key, now)
                a = None
                if ns_records:
                    for ns in ns_records:
                        reduced_key = (ns["RDATA"][0].decode("utf-8"), A_TYPE, sclass)
                        if a := self.check_Cache(reduced_key, now):  # append the ip of name servers
                            slist.extend(random.choice(a)["RDATA"])
                        # slist.append(random.choice(a["RDATA"]))
                else:
                    # TODO Kick off parallel process to look for the ip addresses of said server
                    # reduced_key = (reduced_sname, A_TYPE, sclass)
                    # parallel_thread = threading.Thread(target=self.recursive_lookup, args=(q, *reduced_key, now, 10))
                    # parallel_thread.start()
                    pass
                    # a = recursive_lookup(*reduced_key, now, 10)
            slist.extend(sbelt)

            ### STEP 3 ###
            for ns in slist:
                a = self.query_then_cache(ns, q)

                ### STEP 4 ###
                gotAns = self.check_Cache(key, now)

                ### STEP 4.1 ###
                if (gotAns and a.header["RCODE"] == NOERROR_RCODE) or a.header["RCODE"] == NAMEERROR_RCODE:
                    return a

                ### STEP 4.2 ###
                elif a.answers and (ns_records := [rec for rec in a.answers if rec["TYPE"] == NS_TYPE]):
                    break

                    # # Resolve the NS Record:
                    # # resolved = []
                    # unresolved = []
                    # A_records = [rec for rec in a.answers if rec["TYPE"] == A_TYPE]
                    # # print("NS!!!", ns_records)
                    # # print("IP!!!", A_records)
                    # for ns_record in ns_records:
                    #     match = filter(lambda A_record: A_record["NAME"] == ns_record["RDATA"][0], A_records)
                    #     if match:
                    #         temp = next(match)
                    #         ns = str(temp["RDATA"][0])
                    #         break
                    #     else:
                    #         unresolved.append(ns_record)
                    # else:
                    #     if not unresolved:
                    #         return a
                    #     # No additional section for A records
                    #     ad_hoc_question = copy.copy(q)
                    #     ad_hoc_question.question["NAME"] = unresolved[0]

                    #     resolved_ns = self.query_then_cache(
                    #         ns, ad_hoc_question
                    #     )  # pick any of the unresolved ns records

                    #     temp = [rec for rec in a.answers if rec["TYPE"] == A_TYPE]
                    #     if temp:
                    #         ns = temp[0]["RDATA"][0]
                    #     else:
                    #         return a

                ### STEP 4.3 ###
                elif a.answers and (
                    cname_rec := [rec for rec in a.answers if rec["TYPE"] == CNAME_TYPE]
                ):  # if there is a CNAME Record
                    new_sname = random.choice(cname_rec)["RDATA"][0].decode(
                        "utf-8"
                    )  # TODO Not sure if this is valid works so far
                    print("CNAME -> SNAME", new_sname)
                    return self.recursive_lookup2(new_sname, stype, sclass, now)

                # else:
                #     break


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
