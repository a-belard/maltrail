#!/usr/bin/env python

"""
Copyright (c) 2014-2023 Maltrail developers (https://github.com/stamparm/maltrail/)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function  # Requires: Python >= 2.6

import sys

sys.dont_write_bytecode = True

import cProfile
import inspect
import math
import mmap
import optparse
import os
import platform
import re
import socket
from scapy.all import *
import ipaddress
import subprocess
import struct
import threading
import time
import traceback
import warnings

from core.addr import inet_ntoa6
from core.addr import addr_port
from core.attribdict import AttribDict
from core.common import check_connection
from core.common import check_sudo
from core.common import check_whitelisted
from core.common import get_ex_message
from core.common import get_text
from core.common import is_local
from core.common import load_trails
from core.common import patch_parser
from core.compat import xrange
from core.datatype import LRUDict
from core.enums import BLOCK_MARKER
from core.enums import CACHE_TYPE
from core.enums import PROTO
from core.enums import TRAIL
from core.log import create_log_directory
from core.log import flush_condensed_events
from core.log import get_error_log_handle
from core.log import log_error
from core.parallel import worker
from core.parallel import write_block
from core.settings import config
from core.settings import CAPTURE_TIMEOUT
from core.settings import CHECK_CONNECTION_MAX_RETRIES
from core.settings import CONFIG_FILE
from core.settings import CONSONANTS
from core.settings import DLT_OFFSETS
from core.settings import DNS_EXHAUSTION_THRESHOLD
from core.settings import GENERIC_SINKHOLE_REGEX
from core.settings import HOMEPAGE
from core.settings import HOURLY_SECS
from core.settings import HTTP_TIME_FORMAT
from core.settings import IGNORE_DNS_QUERY_SUFFIXES
from core.settings import IPPROTO_LUT
from core.settings import IS_WIN
from core.settings import LOCALHOST_IP
from core.settings import LOCAL_SUBDOMAIN_LOOKUPS
from core.settings import MAX_CACHE_ENTRIES
from core.settings import MMAP_ZFILL_CHUNK_LENGTH
from core.settings import NAME
from core.settings import NO_SUCH_NAME_COUNTERS
from core.settings import NO_SUCH_NAME_PER_HOUR_THRESHOLD
from core.settings import INFECTION_SCANNING_THRESHOLD
from core.settings import PORT_SCANNING_THRESHOLD
from core.settings import POTENTIAL_INFECTION_PORTS
from core.settings import read_config
from core.settings import REGULAR_SENSOR_SLEEP_TIME
from core.settings import SNAP_LEN
from core.settings import SUSPICIOUS_CONTENT_TYPES
from core.settings import SUSPICIOUS_DIRECT_DOWNLOAD_EXTENSIONS
from core.settings import SUSPICIOUS_DIRECT_IP_URL_REGEX
from core.settings import SUSPICIOUS_DOMAIN_CONSONANT_THRESHOLD
from core.settings import SUSPICIOUS_DOMAIN_ENTROPY_THRESHOLD
from core.settings import SUSPICIOUS_DOMAIN_LENGTH_THRESHOLD
from core.settings import SUSPICIOUS_HTTP_PATH_REGEXES
from core.settings import SUSPICIOUS_HTTP_REQUEST_PRE_CONDITION
from core.settings import SUSPICIOUS_HTTP_REQUEST_REGEXES
from core.settings import SUSPICIOUS_HTTP_REQUEST_FORCE_ENCODE_CHARS
from core.settings import SUSPICIOUS_PROXY_PROBE_PRE_CONDITION
from core.settings import SUSPICIOUS_UA_REGEX
from core.settings import VALID_DNS_NAME_REGEX
from core.settings import trails
from core.settings import VERSION
from core.settings import WEB_SCANNING_THRESHOLD
from core.settings import WHITELIST
from core.settings import WHITELIST_DIRECT_DOWNLOAD_KEYWORDS
from core.settings import WHITELIST_LONG_DOMAIN_NAME_KEYWORDS
from core.settings import WHITELIST_HTTP_REQUEST_PATHS
from core.settings import WHITELIST_UA_REGEX
from core.update import update_ipcat
from core.update import update_trails
from thirdparty import six
from thirdparty.six.moves import urllib as _urllib

#flask and redis
from flask import Flask, request, jsonify
import redis

#responses
from response_types import *

warnings.filterwarnings(action="ignore", category=DeprecationWarning)       # NOTE: https://github.com/helpsystems/pcapy/pull/67/files

_buffer = None
_caps = []
_connect_sec = 0
_connect_src_dst = {}
_connect_src_details = {}
_path_src_dst = {}
_path_src_dst_details = {}
_count = 0
_locks = AttribDict()
_multiprocessing = None
_n = None
_result_cache = LRUDict(MAX_CACHE_ENTRIES)
_local_cache = LRUDict(MAX_CACHE_ENTRIES)
_done_lock = threading.Lock()
_subdomains = {}
_subdomains_sec = None
_dns_exhausted_domains = set()
_request_ip = None
_threat_found = None

class _set(set):
    pass

try:
    import __builtin__
except ImportError:
    # Python 3
    import builtins as __builtin__


def print(*args, **kwargs):
    ret = __builtin__.print(*args, **kwargs)
    sys.stdout.flush()
    return ret

def return_event(event, packet):
    global _request_ip
    global _threat_found
    if _request_ip != None:
        _threat_found = {"reason": event[9], "reference": event[10]}

try:
    import pcapy
except ImportError:
    if IS_WIN:
        sys.exit("[!] please install 'WinPcap' (e.g. 'http://www.winpcap.org/install/') and Pcapy (e.g. 'https://breakingcode.wordpress.com/?s=pcapy')")
    else:
        msg = "[!] please install 'pcapy or pcapy-ng' (e.g. 'sudo pip%s install pcapy-ng')" % ('3' if six.PY3 else '2')

        sys.exit(msg)

def _check_domain_member(query, domains):
    parts = query.lower().split('.')

    for i in xrange(0, len(parts)):
        domain = '.'.join(parts[i:])
        if domain in domains:
            return True

    return False

def _check_domain_whitelisted(query):
    result = _result_cache.get((CACHE_TYPE.DOMAIN_WHITELISTED, query))

    if result is None:
        result = _check_domain_member(re.split(r"(?i)[^A-Z0-9._-]", query or "")[0], WHITELIST)
        _result_cache[(CACHE_TYPE.DOMAIN_WHITELISTED, query)] = result

    return result

def _check_domain(query):
    if query:
        query = query.lower()
        if ':' in query:
            query = query.split(':', 1)[0]

    if query.replace('.', "").isdigit():  # IP address
        return

    if _result_cache.get((CACHE_TYPE.DOMAIN, query)) is False:
        return

    result = False
    if re.search(VALID_DNS_NAME_REGEX, query) is not None and not _check_domain_whitelisted(query):
        parts = query.split('.')

        if query.endswith(".ip-address.com"):  # Reference: https://www.virustotal.com/gui/domain/ip-adress.com/relations
            _ = '.'.join(parts[:-2])
            trail = "%s(.ip-adress.com)" % _
            if _ in trails:
                result = True
                return return_result(trails[_][0], trails[_][1])

        if not result:
            for i in xrange(0, len(parts)):
                domain = '.'.join(parts[i:])
                if domain in trails:
                    if domain == query:
                        trail = domain
                    else:
                        _ = ".%s" % domain
                        trail = "(%s)%s" % (query[:-len(_)], _)

                    if not (re.search(r"(?i)\A([rd]?ns|nf|mx|nic)\d*\.", query) and any(_ in trails.get(domain, " ")[0] for _ in ("suspicious", "sinkhole"))):  # e.g. ns2.nobel.su
                        if not ((query == trail or parts[0] == "www") and any(_ in trails.get(domain, " ")[0] for _ in ("dynamic", "free web"))):  # e.g. noip.com
                            result = True
                            return return_result(trails[domain][0], trails[domain][1])

        if not result and config.USE_HEURISTICS:
            if len(parts[0]) > SUSPICIOUS_DOMAIN_LENGTH_THRESHOLD and '-' not in parts[0]:
                trail = None

                if len(parts) > 2:
                    trail = "(%s).%s" % ('.'.join(parts[:-2]), '.'.join(parts[-2:]))
                elif len(parts) == 2:
                    trail = "(%s).%s" % (parts[0], parts[1])
                else:
                    trail = query

                if trail and not any(_ in trail for _ in WHITELIST_LONG_DOMAIN_NAME_KEYWORDS):
                    result = True
                    return return_result("long domain (suspicious)", "(heuristic)")

        if not result and trails._regex:
            match = re.search(trails._regex, query)
            if match:
                group, trail = [_ for _ in match.groupdict().items() if _[1] is not None][0]
                candidate = trails._regex.split("(?P<")[int(group[1:]) + 1]
                candidate = candidate.split('>', 1)[-1].rstrip('|')[:-1]
                if candidate in trails:
                    result = True
                    trail = match.group(0)

                    prefix, suffix = query[:match.start()], query[match.end():]
                    if prefix:
                        trail = "(%s)%s" % (prefix, trail)
                    if suffix:
                        trail = "%s(%s)" % (trail, suffix)

                    trail = trail.replace(".)", ").")

                    return return_result(trails[candidate][0], trails[candidate][1])

        if not result and ".onion." in query:
            trail = re.sub(r"(\.onion)(\..*)", r"\1(\2)", query)
            _ = trail.split('(')[0]
            if _ in trails:
                result = True
                return return_result(trails[_][0], trails[_][1])

    if result is False:
        _result_cache[(CACHE_TYPE.DOMAIN, query)] = False

def _get_local_prefix():
    _sources = set(_.split('~')[0] for _ in _connect_src_dst.keys())
    _candidates = [re.sub(r"\d+\.\d+\Z", "", _) for _ in _sources]
    _ = sorted(((_candidates.count(_), _) for _ in set(_candidates)), reverse=True)
    result = _[0][1] if _ else ""

    if result:
        _result_cache[(CACHE_TYPE.LOCAL_PREFIX, "")] = result
    else:
        result = _result_cache.get((CACHE_TYPE.LOCAL_PREFIX, ""))

    return result or '_'

# process request
def _process_request(request_ip, user_agent="", content_type=""):
    is_threat_domain = _check_domain(request_ip)
    if is_threat_domain != None:
        return is_threat_domain
    if _request_ip in trails:
        return return_result(trails[_request_ip][0], trails[_request_ip][1]);
    for key in _connect_src_dst:
        if not check_whitelisted(request_ip):
            if not _dst.isdigit() and len(_connect_src_dst[key]) > PORT_SCANNING_THRESHOLD:
                for _ in _connect_src_details[key]:
                    return return_result("potential port scanning", "(heuristic)")
        elif len(_connect_src_dst[key]) > INFECTION_SCANNING_THRESHOLD:
            _dst_port = request_ip
            _dst_ip = [_[-1] for _ in _connect_src_details[key]]
            _src_port = [_[-2] for _ in _connect_src_details[key]]

            if len(_dst_ip) == len(set(_dst_ip)):
                if _src_ip.startswith(_get_local_prefix()):
                    return return_result("potential infection", "(heuristic)")
    
    # user_agent
    if user_agent != "":
        result = _result_cache.get((CACHE_TYPE.USER_AGENT, user_agent))
        if result is None:
            if re.search(WHITELIST_UA_REGEX, user_agent, re.I) is None:
                match = re.search(SUSPICIOUS_UA_REGEX, user_agent)
                if match:
                    def _(value):
                        return value.rstrip('\\').replace('(', "\\(").replace(')', "\\)")

                    parts = user_agent.split(match.group(0), 1)

                    if len(parts) > 1 and parts[0] and parts[-1]:
                        result = _result_cache[(CACHE_TYPE.USER_AGENT, user_agent)] = "%s (%s)" % (_(match.group(0)), _(user_agent))
                    else:
                        result = _result_cache[(CACHE_TYPE.USER_AGENT, user_agent)] = _(match.group(0)).join(("(%s)" if part else "%s") % _(part) for part in parts)
            if not result:
                _result_cache[(CACHE_TYPE.USER_AGENT, user_agent)] = False

        if result:
            return return_result("user agent (suspicious)", "(heuristic)")
    
    # content-type 
    if content_type != "" and content_type in SUSPICIOUS_CONTENT_TYPES:
        return return_result("content type (suspicious)", "(heuristic)")


def return_result(reason, reference):
    global _threat_found
    _threat_found = {"reason": reason, "reference": reference}  

def init():
    """
    Performs sensor initialization
    """

    global _multiprocessing

    try:
        import multiprocessing

        if config.PROCESS_COUNT > 1 and not config.profile:
            _multiprocessing = multiprocessing
    except (ImportError, OSError, NotImplementedError):
        pass

    def update_timer():
        retries = 0
        if not config.offline:
            while retries < CHECK_CONNECTION_MAX_RETRIES and not check_connection():
                sys.stdout.write("[!] can't update because of lack of Internet connection (waiting..." if not retries else '.')
                sys.stdout.flush()
                time.sleep(10)
                retries += 1

            if retries:
                print(")")

        if config.offline or retries == CHECK_CONNECTION_MAX_RETRIES:
            if retries == CHECK_CONNECTION_MAX_RETRIES:
                print("[x] going to continue without online update")
            _ = update_trails(offline=True)
        else:
            _ = update_trails()
            update_ipcat()

        if _:
            trails.clear()
            trails.update(_)
        elif not trails:
            _ = load_trails()
            trails.update(_)

        _regex = ""
        for trail in trails:
            if "static" in trails[trail][1]:
                if re.search(r"[\].][*+]|\[[a-z0-9_.\-]+\]", trail, re.I):
                    try:
                        re.compile(trail)
                    except re.error:
                        pass
                    else:
                        if re.escape(trail) != trail:
                            index = _regex.count("(?P<g")
                            if index < 100:  # Reference: https://stackoverflow.com/questions/478458/python-regular-expressions-with-more-than-100-groups
                                _regex += "|(?P<g%s>%s)" % (index, trail)

        trails._regex = _regex.strip('|')

        thread = threading.Timer(config.UPDATE_PERIOD, update_timer)
        thread.daemon = True
        thread.start()

    create_log_directory()
    get_error_log_handle()

    msg = "[i] using '%s' for trail storage" % config.TRAILS_FILE
    if os.path.isfile(config.TRAILS_FILE):
        mtime = time.gmtime(os.path.getmtime(config.TRAILS_FILE))
        msg += " (last modification: '%s')" % time.strftime(HTTP_TIME_FORMAT, mtime)

    print(msg)

    update_timer()

    if not config.DISABLE_CHECK_SUDO and check_sudo() is False:
        sys.exit("[!] please run '%s' with root privileges" % __file__)

    if config.plugins:
        config.plugin_functions = []
        for plugin in re.split(r"[,;]", config.plugins):
            plugin = plugin.strip()
            found = False

            for _ in (plugin, os.path.join("plugins", plugin), os.path.join("plugins", "%s.py" % plugin)):
                if os.path.isfile(_):
                    plugin = _
                    found = True
                    break

            if not found:
                sys.exit("[!] plugin script '%s' not found" % plugin)
            else:
                dirname, filename = os.path.split(plugin)
                dirname = os.path.abspath(dirname)
                if not os.path.exists(os.path.join(dirname, '__init__.py')):
                    sys.exit("[!] empty file '__init__.py' required inside directory '%s'" % dirname)

                if not filename.endswith(".py"):
                    sys.exit("[!] plugin script '%s' should have an extension '.py'" % filename)

                if dirname not in sys.path:
                    sys.path.insert(0, dirname)

                try:
                    module = __import__(filename[:-3])
                except (ImportError, SyntaxError) as msg:
                    sys.exit("[!] unable to import plugin script '%s' (%s)" % (filename, msg))

                found = False
                for name, function in inspect.getmembers(module, inspect.isfunction):
                    if name == "plugin" and not set(inspect.getargspec(function).args) & set(("event_tuple', 'packet")):
                        found = True
                        config.plugin_functions.append(function)
                        function.__name__ = module.__name__

                if not found:
                    sys.exit("[!] missing function 'plugin(event_tuple, packet)' in plugin script '%s'" % filename)

    if config.REMOTE_SEVERITY_REGEX:
        try:
            re.compile(config.REMOTE_SEVERITY_REGEX)
        except re.error:
            sys.exit("[!] invalid configuration value for 'REMOTE_SEVERITY_REGEX' ('%s')" % config.REMOTE_SEVERITY_REGEX)

    if _multiprocessing:
        _init_multiprocessing()


def validIPAddress(IP: str) -> str:
    try:
        return 4 if ipaddress.ip_address(IP).version == 4 else 6
    except ValueError:
        return None
        
            
# flask app
app = Flask(__name__)   

hostname=socket.gethostname()
IPAddr=socket.gethostbyname(hostname)
redis_client = redis.Redis(host="localhost", port=6379)

@app.route('/v1/sensor', methods=['POST'])
def fetch_events():
    global _request_ip
    global _threat_found
    
    data = request.get_json()
    
    # validations    
    if 'type' not in data or data['type'] == "":
        return RequiredResponse("Type").get_obj()
    
    type = data['type']
    if type == "IP":
        if 'ip_address' not in data or data["ip_address"] == "": 
            return RequiredResponse("IP address").get_obj()
        ip_version = validIPAddress(data['ip_address'])
        if ip_version == None:
            return InvalidResponse("IP address").get_obj()
        _request_ip = data['ip_address']
    elif type == "DOMAIN":
        if 'domain_name' not in data or data["domain_name"] == "":
            return RequiredResponse("domain name").get_obj()
        _request_ip = data['domain_name']
    else:
        return InvalidResponse("Type").get_obj()
    
    current_timestamp = int(time.time())
    N = int(config.N)
    ttl = int(config.TTL) * 60 * 60 
    
    if redis_client.lrange(_request_ip, 0, -1) != None:
        prev_timestamps = redis_client.lrange(_request_ip, 0, -1)
        for timestamp in prev_timestamps:
            timestamp = int(timestamp)
            if current_timestamp - timestamp < 1:
                req_count = redis_client.llen(_request_ip)
                if req_count >= N:
                    return {
                        "statusCode": 200,
                        "ip_address": _request_ip,
                        "reason": "Dos/DDos suspected!",
                        "severity": "HIGH",
                        "timestamp": current_timestamp,
                        "references": "",
                    }
        redis_client.rpush(_request_ip, current_timestamp)
        redis_client.expire(_request_ip, ttl)
    else:
        redis_client.rpush(_request_ip, current_timestamp)
        redis_client.expire(_request_ip, ttl)

    user_agent = ""
    content_type = ""
    if "user_agent" in data:
        user_agent = data['user_agent']
    if "content_type" in data:
        content_type = data['content_type']
        
    result = {}
    result['statusCode'] = 200        
    result['timestamp'] = int(time.time())
    if user_agent != "":
        result['user-agent'] = user_agent
    if content_type != "":
        result["content-type"] = content_type
    if type == "IP":
        result["ip_address"] = _request_ip
    else:
        result["domain_name"] = _request_ip
    
    _process_request(_request_ip, user_agent, content_type)
    
    is_threat_found = _threat_found
    if(is_threat_found != None):
        result.update(_threat_found)

    if is_threat_found == None:
        try:
            ip = IP(src=_request_ip, dst=_request_ip)
        except Exception:
            return InvalidResponse("domain name").get_obj()

        result['reason'] = "No threat found"
        result['references'] = ""
        result['severity'] =  "LOW"
        return result
    
        
    # set severity
    SEVERITY = {
        "LOW": "LOW",
        "MEDIUM": "MEDIUM",
        "HIGH": "HIGH"
    }
    INFO_SEVERITY_KEYWORDS = {
        "malware": SEVERITY["HIGH"],
        "adversary": SEVERITY["HIGH"],
        "ransomware": SEVERITY["HIGH"],
        "reputation": SEVERITY["LOW"],
        "attacker": SEVERITY["LOW"],
        "spammer": SEVERITY["LOW"],
        "compromised": SEVERITY["LOW"],
        "crawler": SEVERITY["LOW"],
        "scanning": SEVERITY["LOW"],
        "user agent": SEVERITY["HIGH"],
        "content type": SEVERITY["MEDIUM"]
    }
    threat_severity = ""
    if "(custom)" in result["reference"]:
            threat_severity = SEVERITY["HIGH"];
    elif "(remote custom)" in result["reference"]:
        threat_severity = SEVERITY["HIGH"];
    elif "potential malware site" in result["reason"]: 
        threat_severity = SEVERITY["MEDIUM"];
    elif "malwaredomainlist" in result["reference"]:
        threat_severity = SEVERITY["HIGH"];
    elif "malware distribution" in result["reason"]:
        threat_severity = SEVERITY["MEDIUM"];
    elif "mass scanner" in result["reason"]:
        threat_severity = SEVERITY["LOW"];
    else:
        for keyword in INFO_SEVERITY_KEYWORDS:
            if keyword in result["reason"]:
                threat_severity = INFO_SEVERITY_KEYWORDS[keyword];
                break;
    result["severity"] = threat_severity
    
    # clear threat_found and request_ip
    _threat_found = None
    _request_ip = None

    # Return the events as a JSON response
    return result


def main():
    parser = optparse.OptionParser(version=VERSION)
    parser.add_option("-c", dest="config_file", default=CONFIG_FILE, help="configuration file (default: '%s')" % os.path.split(CONFIG_FILE)[-1])
    parser.add_option("-r", dest="pcap_file", help="pcap file for offline analysis")
    parser.add_option("-p", dest="plugins", help="plugin(s) to be used per event")
    parser.add_option("-q", "--quiet", dest="quiet", action="store_true", help="turn off regular output")
    parser.add_option("--console", dest="console", action="store_true", help="print events to console")
    parser.add_option("--offline", dest="offline", action="store_true", help="disable (online) trail updates")
    parser.add_option("--debug", dest="debug", action="store_true", help=optparse.SUPPRESS_HELP)
    parser.add_option("--profile", dest="profile", help=optparse.SUPPRESS_HELP)

    patch_parser(parser)

    options, _ = parser.parse_args()

    print("[*] starting @ %s\n" % time.strftime("%X /%Y-%m-%d/"))

    read_config(options.config_file)

    for option in dir(options):
        if isinstance(getattr(options, option), (six.string_types, bool)) and not option.startswith('_'):
            config[option] = getattr(options, option)

    if options.debug:
        config.console = True
        config.PROCESS_COUNT = 1
        config.SHOW_DEBUG = True
    
    try:
        init()
    except KeyboardInterrupt:
        print("\r[x] stopping (Ctrl-C pressed)")

    if not config.DISABLE_CHECK_SUDO and not check_sudo():
        sys.exit("[!] please run '%s' with root privileges" % __file__)
        
    app.run()

if __name__ == "__main__":
    code = 0

    try:
        main()
    except SystemExit as ex:
        if isinstance(get_ex_message(ex), six.string_types) and get_ex_message(ex).strip('0'):
            print(get_ex_message(ex))
            code = 1
    except IOError:
        log_error("\n\n[!] session abruptly terminated\n[?] (hint: \"https://stackoverflow.com/a/20997655\")")
        code = 1
    except Exception:
        msg = "\r[!] unhandled exception occurred ('%s')" % sys.exc_info()[1]
        msg += "\n[x] please report the following details at 'https://github.com/stamparm/maltrail/issues':\n---\n'%s'\n---" % traceback.format_exc()
        log_error("\n\n%s" % msg.replace("\r", ""))

        print(msg)
        code = 1
    finally:
        if not any(_ in sys.argv for _ in ("--version", "-h", "--help")):
            print("\n[*] ending @ %s" % time.strftime("%X /%Y-%m-%d/"))
