import time
import json
import os
from urllib.parse import urlencode
import logging
import ipaddress
import select
from socket import ntohl, htonl
import ctypes
import urllib3

# Configuration from environment variables with defaults
VPN_GW = os.getenv('VPN_GATEWAY', '10.2.0.1')
QB_URL = os.getenv('QB_URL', 'http://127.0.0.1:9080')

#########################################################################################################
# Logging
logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.INFO)
logger = logging.getLogger(__name__)

# Log configuration
logger.info(f"Using VPN Gateway: {VPN_GW}")
logger.info(f"Using qBittorrent URL: {QB_URL}")

#########################################################################################################
# NAT-PMP
NATPMP_TRYAGAIN = -100
NATPMP_RESPTYPE_PUBLICADDRESS = 0
NATPMP_RESPTYPE_UDPPORTMAPPING = 1
NATPMP_RESPTYPE_TCPPORTMAPPING = 2
NATPMP_PROTOCOL_UDP = 1
NATPMP_PROTOCOL_TCP = 2

if ctypes.sizeof(ctypes.c_void_p) == ctypes.sizeof(ctypes.c_int64):
    _time_t = ctypes.c_int64
    _suseconds_t = ctypes.c_int64
else:
    _time_t = ctypes.c_int32
    _suseconds_t = ctypes.c_int32

class _timeval(ctypes.Structure):
    _fields_ = [
        ('tv_sec', _time_t),
        ('tv_usec', _suseconds_t)
    ]

class _natpmp_t(ctypes.Structure):
    _fields_ = [
        ('s', ctypes.c_int),
        ('gateway', ctypes.c_uint32),
        ('has_pending_request', ctypes.c_int),
        ('pending_request', ctypes.c_char * 12),
        ('pending_request_len', ctypes.c_int),
        ('try_number', ctypes.c_int),
        ('retry_time', _timeval) # Assuming struct timeval is two ints
    ]

class _newportmapping_t(ctypes.Structure):
    _fields_ = [
        ('privateport', ctypes.c_uint16),
        ('mappedpublicport', ctypes.c_uint16),
        ('lifetime', ctypes.c_uint32)
    ]

class _publicaddress_t(ctypes.Structure):
    _fields_ = [("addr", ctypes.c_uint32)] # You can also use socket.in_addr

class _newportmapping_t(ctypes.Structure):
    _fields_ = [("privateport", ctypes.c_uint16),
                ("mappedpublicport", ctypes.c_uint16),
                ("lifetime", ctypes.c_uint32)]

class _pnu_t(ctypes.Union):
    _fields_ = [("publicaddress", _publicaddress_t),
                ("newportmapping", _newportmapping_t)]

class natpmpresp_t(ctypes.Structure):
    _fields_ = [("type", ctypes.c_uint16),
                ("resultcode", ctypes.c_uint16),
                ("epoch", ctypes.c_uint32),
                ("pnu", _pnu_t)]

_libnatpmp = ctypes.CDLL('libnatpmp.so')
_libnatpmp.strnatpmperr.argtypes = [ctypes.c_int]
_libnatpmp.strnatpmperr.restype = ctypes.c_char_p
_libnatpmp.initnatpmp.argtypes = [ctypes.POINTER(_natpmp_t), ctypes.c_int, ctypes.c_uint32]
_libnatpmp.initnatpmp.restype = ctypes.c_int
_libnatpmp.closenatpmp.argtypes = [ctypes.POINTER(_natpmp_t)]
_libnatpmp.closenatpmp.restype = ctypes.c_int
_libnatpmp.sendpublicaddressrequest.argtypes = [ctypes.POINTER(_natpmp_t)]
_libnatpmp.sendpublicaddressrequest.restype = ctypes.c_int
_libnatpmp.sendnewportmappingrequest.argtypes = [ctypes.POINTER(_natpmp_t), ctypes.c_int, ctypes.c_uint16, ctypes.c_uint16, ctypes.c_uint32]
_libnatpmp.sendnewportmappingrequest.restype = ctypes.c_int


_reserved_addresses = [
    ipaddress.ip_network('0.0.0.0/8'),        # RFC1122: "This host on this network"
    ipaddress.ip_network('10.0.0.0/8'),       # RFC1918: Private-Use
    ipaddress.ip_network('100.64.0.0/10'),    # RFC6598: Shared Address Space
    ipaddress.ip_network('127.0.0.0/8'),      # RFC1122: Loopback
    ipaddress.ip_network('169.254.0.0/16'),   # RFC3927: Link-Local
    ipaddress.ip_network('172.16.0.0/12'),    # RFC1918: Private-Use
    ipaddress.ip_network('192.0.0.0/24'),     # RFC6890: IETF Protocol Assignments
    ipaddress.ip_network('192.0.2.0/24'),     # RFC5737: Documentation (TEST-NET-1)
    ipaddress.ip_network('192.31.196.0/24'),  # RFC7535: AS112-v4
    ipaddress.ip_network('192.52.193.0/24'),  # RFC7450: AMT
    ipaddress.ip_network('192.88.99.0/24'),   # RFC7526: 6to4 Relay Anycast
    ipaddress.ip_network('192.168.0.0/16'),   # RFC1918: Private-Use
    ipaddress.ip_network('192.175.48.0/24'),  # RFC7534: Direct Delegation AS112 Service
    ipaddress.ip_network('198.18.0.0/15'),    # RFC2544: Benchmarking
    ipaddress.ip_network('198.51.100.0/24'),  # RFC5737: Documentation (TEST-NET-2)
    ipaddress.ip_network('203.0.113.0/24'),   # RFC5737: Documentation (TEST-NET-3)
    ipaddress.ip_network('224.0.0.0/4'),      # RFC1112: Multicast
    ipaddress.ip_network('240.0.0.0/4'),      # RFC1112: Reserved for Future Use + RFC919 Limited Broadcast
]

def _addr_is_reserved(ip_address):
    for network in _reserved_addresses:
        if ip_address in network:
            return True
    return False

class NatPmpError(Exception):
    def __init__(self, message, error_code=None):
        super().__init__(message)
        self.error_code = error_code

class NatPmpClient(object):
    def __init__(self, gateway : ipaddress.IPv4Address = None):
        self.gateway = ipaddress.IPv4Address(gateway)
        self._natpmp = _natpmp_t()
        self._timeout = _timeval()
        self._response = natpmpresp_t()

        if not self._init_natpmp():
            raise NatPmpError("Failed to initialize NATPMP")

    def _init_natpmp(self):
        if self.gateway is not None:
            r = _libnatpmp.initnatpmp(ctypes.byref(self._natpmp), 1, htonl(int(self.gateway)))
        else:
            r = _libnatpmp.initnatpmp(ctypes.byref(self._natpmp), 0, 0)

        if(r < 0):
            raise NatPmpError(f"initnatpmp() failed with error code {r}", r)

        if self.gateway is None:
            logger.info(f"using gateway : {ipaddress.ip_address(ntohl(self._natpmp.gateway))}")
        return True

    def get_publicaddress(self):
        r = _libnatpmp.sendpublicaddressrequest(ctypes.byref(self._natpmp))
        if r < 0:
            raise NatPmpError(f"sendpublicaddressrequest() failed with error code {r}", r)

        # logger.info(f"sendpublicaddressrequest() returned {r} ({'SUCCESS' if r==2 else 'FAILED'})")
        self._get_response(NATPMP_RESPTYPE_PUBLICADDRESS)

        public_address = ipaddress.ip_address(ntohl(self._response.pnu.publicaddress.addr))

        if _addr_is_reserved(public_address):
            raise NatPmpError(f"Invalid Public IP address {public_address}")

        return public_address

    def portmap(self, protocol : int, private_port : int = 0, public_port : int = 0, lifetime : int = 3600):
        if protocol not in [NATPMP_PROTOCOL_UDP, NATPMP_PROTOCOL_TCP]:
            raise ValueError("Invalid protocol")

        r = _libnatpmp.sendnewportmappingrequest(ctypes.byref(self._natpmp), protocol, 0, 0, 3600)
        if r != 12:
            raise NatPmpError(f"sendnewportmappingrequest() failed with error code {r}", r)

        # logger.info(f"sendnewportmappingrequest returned {r} ({'SUCCESS' if r==12 else 'FAILED'})")
        self._get_response(NATPMP_RESPTYPE_UDPPORTMAPPING if protocol==NATPMP_PROTOCOL_UDP else NATPMP_RESPTYPE_TCPPORTMAPPING)

        return {
            'public_port': self._response.pnu.newportmapping.mappedpublicport,
            'private_port': self._response.pnu.newportmapping.privateport,
            'epoch': self._response.epoch,
            'lifetime': self._response.pnu.newportmapping.lifetime
        }

    def _get_response(self, response_type : int):
        while True:
            _libnatpmp.getnatpmprequesttimeout(ctypes.byref(self._natpmp), ctypes.byref(self._timeout))

            # Convert the timeval to a floating-point number of seconds
            timeout_seconds = self._timeout.tv_sec + self._timeout.tv_usec / 1e6

            select.select([self._natpmp.s], [], [], timeout_seconds)

            r = _libnatpmp.readnatpmpresponseorretry(ctypes.byref(self._natpmp), ctypes.byref(self._response));

            # logger.info(f"readnatpmpresponseorretry returned {r} ({'OK' if r==0 else ('TRY AGAIN' if r==NATPMP_TRYAGAIN else 'FAILED')})")
            if r<0 and r!=NATPMP_TRYAGAIN:
                logging.error(f"readnatpmpresponseorretry() failed : '{_libnatpmp.strnatpmperr(r).decode('utf-8')}'")

            if (r >= 0 and self._response.type != response_type):
                retry = self._natpmp.try_number <= 9
                logger.info(f"readnatpmpresponseorretry received unexpected reply type {self._response.type} (expected {response_type}), {'retrying' if retry == 1 else 'no more retry'}...")

                if retry:
                    r = NATPMP_TRYAGAIN
                    self._natpmp.has_pending_request = 1

            if(r != NATPMP_TRYAGAIN): break

        if r<0: raise NatPmpError(f"Failed to read response : {_libnatpmp.strnatpmperr(r).decode('utf-8')}", error_code=r)

    def close(self):
        r = _libnatpmp.closenatpmp(ctypes.byref(self._natpmp))
        if(r<0): raise NatPmpError(f"Failed to close NATPMP : {_libnatpmp.strnatpmperr(r).decode('utf-8')}", error_code=r)

    def __del__(self):
        try:
            self.close()
        except NatPmpError as e:
            pass

###############################################################################
# qBittorrent
_http = urllib3.PoolManager()
def update_qbittorrent(**kwargs):
    url = f"{QB_URL}/api/v2/app/setPreferences"
    data_encoded = urlencode({"json": json.dumps(kwargs)})

    response = _http.request(
        'POST',
        url,
        body=data_encoded,
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )

    if response.status != 200:
        raise Exception(f"Failed to update qBittorrent : {response.status}")

###############################################################################
def refresh_qb_port():
    npc = NatPmpClient(VPN_GW)
    public_ip = npc.get_publicaddress()
    tcp_portmap = npc.portmap(NATPMP_PROTOCOL_TCP)
    udp_portmap = npc.portmap(NATPMP_PROTOCOL_UDP, private_port=tcp_portmap['private_port'], public_port=tcp_portmap['public_port'])

    logger.info(f"TCP port mapping : {public_ip}:{tcp_portmap['public_port']} -> local:{tcp_portmap['private_port']}")
    logger.info(f"UDP port mapping : {public_ip}:{udp_portmap['public_port']} -> local:{udp_portmap['private_port']}")

    update_qbittorrent(listen_port=tcp_portmap['private_port'], random_port=False, upnp=False)
    npc.close()
    return {
        'tcp_portmap': tcp_portmap,
        'udp_portmap': udp_portmap,
        'public_ip': public_ip
    }

# Main
if __name__ == "__main__":
    next_refresh = time.time()
    sleep_time = 10
    while True:
        logger.info("Refreshing qBittorrent port...")
        try:
            result = refresh_qb_port()
            sleep_time = max(result['tcp_portmap']['lifetime'], 30)
        except Exception as e:
            logging.error(e)

        next_refresh = time.time() + sleep_time - 5
        time.sleep(next_refresh - time.time())
