from os import WIFSTOPPED
from resolver_backround import DnsResolver
import threading
import socket
import argparse
from sys import argv
from helper_funcs import DNSQuery
from datetime import datetime, timedelta
from collections import defaultdict, OrderedDict
import random
import ipaddress
import copy
import itertools
import select

MAX_LEVEL = 10  # max number of iterative queries we make before we stop
CACHE_SIZE = 100000

# TYPE Values
A_TYPE = 1
NS_TYPE = 2
CNAME_TYPE = 5
SOA_TYPE = 6
WKS_TYPE = 11
PTR_TYPE = 12
HINFO_TYPE = 13
MINFO_TYPE = 14
MX_TYPE = 15
TXT_TYPE = 16
ANY_TYPE = 255
TYPES = [A_TYPE, NS_TYPE, CNAME_TYPE, SOA_TYPE, WKS_TYPE, PTR_TYPE, HINFO_TYPE, MINFO_TYPE, MX_TYPE, TXT_TYPE]

# RCODE Values
NOERROR_RCODE = 0
SERVFAIL_RCODE = 2
NAMEERROR_RCODE = 3
REFUSED_RCODE = 5


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

    def check_Cache(self, key, now):

        a = self.cache.get(key)

        if a:
            a = [record for record in a if record["expire_time"] > now]  # Get rid of expired records
            self.cache.put(key, a if a else None)
            return list(map(lambda rec: rec["resp"], a))
        return None

    def check_Cache_ret_time(self, key, now):
        ### Only difference is that this method also returns the expire time
        a = self.cache.get(key)
        if a:
            a = [record for record in a if record["expire_time"] > now]  # Get rid of expired records
            self.cache.put(key, a if a else None)
            return a
        return None

    def check_timeout(self, q, now, limit):
        if (datetime.now() - now) > timedelta(seconds=limit):
            if not __debug__:
                print("Query Timed Out [1]", q, datetime.now(), now)
            q.header["QR"] = 1
            q.header["RCODE"] = SERVFAIL_RCODE
            q.header["ANCOUNT"] = 0
            q.header["NSCOUNT"] = 0
            q.header["ARCOUNT"] = 0
            q.answers = []
            return q
        return None

    def query_then_cache(self, destination_address_1, q):
        ### Query
        ### https://tools.ietf.org/html/rfc5452#section-9

        destination_port_1 = 53

        old_id = copy.copy(q.header["ID"])

        q.header["ID"] = random.randint(0, 65535)

        q_id_1, q_name_1, q_type_1, q_class_1 = (
            q.header["ID"],
            q.question["NAME"],
            q.question["QTYPE"],
            q.question["QCLASS"],
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        sock.bind(("", 0))
        destination_address_1 = str(ipaddress.ip_address(destination_address_1))

        sock.connect((destination_address_1, destination_port_1))

        q.header["RD"] = 0  # we do not want recursive query
        q.header["QR"] = 0
        q.header["ANCOUNT"] = 0
        q.header["NSCOUNT"] = 0
        q.header["NSCOUNT"] = 0
        q.header["ARCOUNT"] = 0
        q.answers = []
        sock.sendall(q.to_bytes())
        if not __debug__:
            print(f"Q {destination_address_1}: ", q)

        read, _, _ = select.select([sock], [], [], 8)  # Timeout after 15 sec
        if read:
            answer, (destination_address_2, destination_port_2) = sock.recvfrom(1024)
        else:
            q.header["ID"] = old_id
            return q

        if destination_address_1 != destination_address_2 or destination_port_1 != destination_port_2:
            q.header["ID"] = old_id
            return q  # address/port do not match

        sock.close()

        a = DNSQuery(answer)

        q_id_2, q_name_2, q_type_2, q_class_2 = (
            a.header["ID"],
            a.question["NAME"],
            a.question["QTYPE"],
            a.question["QCLASS"],
        )

        if q_id_1 != q_id_2 or q_name_1 != q_name_2 or q_type_1 != q_type_2 or q_class_1 != q_class_2:
            q.header["ID"] = old_id
            return q  # id/name/type/class do not match

        ### Caching
        if a.header["RCODE"] == NOERROR_RCODE:
            new_rr = defaultdict(list)
            for record in a.answers:
                key = (
                    record["NAME"].decode("utf-8").lower(),
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

        # TODO Support Negative Caching
        # https://tools.ietf.org/html/rfc2308#section-5 and section-6
        # else a.header["RCODE"] == NXDOMAIN ...

        if not __debug__:
            print("A: ", a)

        q.header["ID"] = old_id
        a.header["ID"] = old_id
        return a

    def get_dns_response(self, query):
        # input: A query and any state in self
        # returns: the correct response to the query obtained by asking DNS name servers
        # Your code goes here, when you change any 'self' variables make sure to use a lock
        q = DNSQuery(query)
        if not __debug__:
            print("Query: ", q)

        ### Reject EDNS Reference: https://tools.ietf.org/html/rfc6891#section-6
        if q.header["ARCOUNT"] and any(rec["TYPE"] == 41 for rec in q.answers):
            q.header["QR"] = 1
            q.header["RD"] = 0
            q.header["RA"] = 0
            q.header["RCODE"] = REFUSED_RCODE
            q.header["ANCOUNT"] = 0
            q.header["NSCOUNT"] = 0
            q.header["ARCOUNT"] = 0
            q.answers = []
            return q.to_bytes()  ### RETURNING

        sname, stype, sclass = (
            q.question["NAME"].decode("utf-8").lower(),
            q.question["QTYPE"],
            q.question["QCLASS"],
        )

        ### TODO Handle norecurse
        #

        ### Handle ANY Query
        # Traverse through cache get anything that matches with sname
        if stype == ANY_TYPE:
            q.header["QR"] = 1
            q.header["AA"] = 0  # Because result is from a cache
            q.header["RA"] = 1
            now = datetime.now()
            for record_type in TYPES:
                new_key = (sname, record_type, sclass)
                if (a := self.check_Cache_ret_time(new_key, now)) :
                    for record in a:
                        record["resp"]["TTL"] = int((record["expire_time"] - now).total_seconds())
                    q.answers.extend([rec["resp"] for rec in a])
            q.header["ANCOUNT"] = len(q.answers)
            return q.to_bytes()

        return self.recursive_lookup(
            q, sname, stype, sclass, datetime.now()
        ).to_bytes()  # NOTE datetime.now() was not updating until I added in as a parameter

    def recursive_lookup(self, q, sname, stype, sclass, now=datetime.now(), limit=60):
        key = (sname, stype, sclass)
        ### STEP 1 ###
        if (a := self.check_Cache_ret_time(key, now)) :
            q.header["QR"] = 1
            q.header["ANCOUNT"] = len(a)
            q.header["AA"] = 0  # Because result is from a cache
            q.header["RA"] = 1
            for record in a:
                record["resp"]["TTL"] = int(
                    (record["expire_time"] - datetime.now()).total_seconds()
                )  # UPDATE the TTL of records
            q.answers = [rec["resp"] for rec in a]
            return q  ### RETURNING

        while True:
            if (a := self.check_timeout(q, now, limit)) :  # Query has taken too long
                return a

            slist = self.build_slist(q, *key, now)
            if not __debug__:
                print("SLIST: ", slist)
            ### STEP 3 ###
            for ns in slist:
                a = self.query_then_cache(ns, q)

                ### STEP 4 ###
                gotAns = self.check_Cache(key, now)

                ### STEP 4.1 ###
                if (
                    (gotAns and a.header["RCODE"] == NOERROR_RCODE)  # we found an Answer
                    or a.header["RCODE"] == NAMEERROR_RCODE  # there was a name error
                    or (a.header["AA"] == 1 and [rec for rec in a.answers if rec["TYPE"] == SOA_TYPE])  # SOA response
                    or (
                        q.header["ANCOUNT"] and [rec for rec in a.answers if rec["TYPE"] == A_TYPE]
                    )  # found an ans but name does not match quetion name
                ):
                    a.header["AA"] = 0
                    a.header["RA"] = 1
                    return a  ### RETURNING

                ### STEP 4.2 ###
                elif [rec for rec in a.answers if rec["TYPE"] == NS_TYPE]:  # NSNAME
                    break

                ### STEP 4.3 ###
                elif (cname_rec := [rec for rec in a.answers if rec["TYPE"] == CNAME_TYPE]) :  # CNAME
                    new_sname = random.choice(cname_rec)["RDATA"][0]
                    original_name = q.question["NAME"]
                    q.question["NAME"] = new_sname
                    resp = self.recursive_lookup(q, new_sname.decode("utf-8").lower(), stype, sclass, now)
                    resp.question["NAME"] = original_name
                    return resp

    def build_slist(self, q, sname, stype, sclass, now) -> list:
        ### STEP 2 ###
        sbelt = [
            "198.41.0.4",  # root A
            "199.9.14.201",  # root B
            "195.129.12.83",  # dutch
        ]
        mat_slist = defaultdict(list)
        split_sname = sname.split(".")
        for i in range(len(split_sname)):
            slist = []
            reduced_sname = ".".join(split_sname[i:])
            if not reduced_sname:
                continue
            reduced_key = (reduced_sname, A_TYPE, sclass)
            if a := self.check_Cache(reduced_key, now):  # append the ip of name servers
                slist.extend([rec["RDATA"][0] for rec in a])

            reduced_key = (reduced_sname, NS_TYPE, sclass)
            ns_records = self.check_Cache(reduced_key, now)
            if ns_records:
                for ns in ns_records:
                    ns_name = ns["RDATA"][0]
                    reduced_key = (ns_name.decode("utf-8").lower(), A_TYPE, sclass)
                    if a := self.check_Cache(reduced_key, now):
                        slist.extend([rec["RDATA"][0] for rec in a])
                if not slist:
                    ### SINGLE THREAD for now
                    original_name = q.question["NAME"]
                    for ns in ns_records:
                        ns_name = ns["RDATA"][0]
                        q.question["NAME"] = ns_name
                        reduced_key = (ns_name.decode("utf-8").lower(), A_TYPE, sclass)
                        _ = self.recursive_lookup(q, *reduced_key, now)
                        if a := self.check_Cache(reduced_key, now):
                            slist.extend([rec["RDATA"][0] for rec in a])

                    q.question["NAME"] = original_name

            mat_slist[reduced_sname] = slist

        mat_slist["."] = sbelt
        if not __debug__:
            for k, value in mat_slist.items():
                if k == ".":
                    continue
                print(k, ":", [socket.inet_ntoa(v) for v in value])

        slist = list(itertools.chain.from_iterable(mat_slist.values()))  # flatten mat_slist
        return slist


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
