import time
import json
import os
from urllib.parse import urlencode
import logging
import socket
import struct
import urllib3

# Configuration from environment variables with defaults
VPN_GW = os.getenv('VPN_GATEWAY', '10.2.0.1')
QB_URL = os.getenv('QB_URL', 'http://127.0.0.1:9080')
QB_USER = os.getenv('QB_USER', 'admin')
QB_PASS = os.getenv('QB_PASS', 'admin')

#########################################################################################################
# Logging
logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.INFO)
logger = logging.getLogger(__name__)

# Log configuration
logger.info(f"Using VPN Gateway: {VPN_GW}")
logger.info(f"Using qBittorrent URL: {QB_URL}")
logger.info(f"Using qBittorrent User: {QB_USER}")

#########################################################################################################
# NAT-PMP Implementation
class NatPmpError(Exception):
    def __init__(self, message, error_code=None):
        super().__init__(message)
        self.error_code = error_code

class NatPmpClient(object):
    def __init__(self, gateway: str, timeout: float = 5.0):
        self.gateway = gateway
        self.timeout = timeout
        self.sock = None

    def _send_request(self, request_data: bytes) -> bytes:
        """Send NAT-PMP request and return response"""
        if self.sock is None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.settimeout(self.timeout)
        
        try:
            self.sock.sendto(request_data, (self.gateway, 5351))
            response, addr = self.sock.recvfrom(16)  # NAT-PMP responses are max 16 bytes
            return response
        except socket.timeout:
            raise NatPmpError("NAT-PMP request timed out")
        except Exception as e:
            raise NatPmpError(f"NAT-PMP communication failed: {e}")

    def get_public_address(self) -> str:
        """Get public IP address via NAT-PMP"""
        # NAT-PMP public address request: version(0) + opcode(0)
        request = struct.pack('!BB', 0, 0)
        
        response = self._send_request(request)
        
        if len(response) < 12:
            raise NatPmpError(f"Invalid response length: {len(response)}")
        
        # Parse response: version, opcode, result, epoch, public_ip
        version, opcode, result, epoch, public_ip = struct.unpack('!BBHIL', response)
        
        if version != 0:
            raise NatPmpError(f"Invalid NAT-PMP version: {version}")
        
        if opcode != 0x80:  # Public address response
            raise NatPmpError(f"Unexpected response opcode: {opcode:#x}")
        
        if result != 0:
            raise NatPmpError(f"NAT-PMP error result: {result}")
        
        # Convert IP to string
        public_ip_str = socket.inet_ntoa(struct.pack('!I', public_ip))
        logger.info(f"Got public IP: {public_ip_str}")
        
        return public_ip_str

    def create_port_mapping(self, protocol: str, internal_port: int = 0, external_port: int = 0, lifetime: int = 3600) -> dict:
        """Create port mapping via NAT-PMP"""
        if protocol.upper() not in ['TCP', 'UDP']:
            raise ValueError("Protocol must be 'TCP' or 'UDP'")
        
        # NAT-PMP port mapping request
        # version(0) + opcode(1=UDP, 2=TCP) + reserved(0) + internal_port + external_port + lifetime
        opcode = 1 if protocol.upper() == 'UDP' else 2
        request = struct.pack('!BBHHHL', 0, opcode, 0, internal_port, external_port, lifetime)
        
        response = self._send_request(request)
        
        if len(response) < 16:
            raise NatPmpError(f"Invalid port mapping response length: {len(response)}")
        
        # Parse response: version, opcode, result, epoch, internal_port, external_port, lifetime
        version, resp_opcode, result, epoch, resp_internal, resp_external, resp_lifetime = struct.unpack('!BBHIHHL', response)
        
        if version != 0:
            raise NatPmpError(f"Invalid NAT-PMP version: {version}")
        
        expected_opcode = 0x81 if protocol.upper() == 'UDP' else 0x82
        if resp_opcode != expected_opcode:
            raise NatPmpError(f"Unexpected response opcode: {resp_opcode:#x}, expected: {expected_opcode:#x}")
        
        if result != 0:
            raise NatPmpError(f"Port mapping failed with result: {result}")
        
        mapping_info = {
            'protocol': protocol.upper(),
            'internal_port': resp_internal,
            'external_port': resp_external,
            'lifetime': resp_lifetime,
            'epoch': epoch
        }
        
        logger.info(f"{protocol.upper()} port mapping: {resp_external} -> {resp_internal} (lifetime: {resp_lifetime}s)")
        
        return mapping_info

    def close(self):
        """Close the socket"""
        if self.sock:
            self.sock.close()
            self.sock = None

    def __del__(self):
        self.close()

###############################################################################
# qBittorrent API
_http = urllib3.PoolManager()
_session_cookie = None

def _login_qbittorrent():
    """Login to qBittorrent and get session cookie"""
    global _session_cookie
    
    login_data = f"username={QB_USER}&password={QB_PASS}"
    response = _http.request(
        'POST',
        f"{QB_URL}/api/v2/auth/login",
        body=login_data,
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )
    
    if response.status != 200:
        raise Exception(f"qBittorrent login failed: HTTP {response.status}")
    
    if response.data.decode().strip() != "Ok.":
        raise Exception("qBittorrent login failed: Invalid credentials")
    
    # Get session cookie
    for header_name, header_value in response.headers.items():
        if header_name.lower() == 'set-cookie':
            _session_cookie = header_value
            logger.info("Successfully logged into qBittorrent")
            return
    
    # Some qBittorrent versions don't use cookies, login success is enough
    _session_cookie = "logged_in"
    logger.info("qBittorrent login successful (no cookie)")

def update_qbittorrent(**kwargs):
    """Update qBittorrent preferences"""
    global _session_cookie
    
    # Login if we haven't already
    if _session_cookie is None:
        _login_qbittorrent()
    
    url = f"{QB_URL}/api/v2/app/setPreferences"
    data_encoded = urlencode({"json": json.dumps(kwargs)})
    
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    if _session_cookie and _session_cookie != "logged_in":
        headers['Cookie'] = _session_cookie

    response = _http.request(
        'POST',
        url,
        body=data_encoded,
        headers=headers
    )

    if response.status == 403:
        # Try to login again
        logger.info("Got 403, attempting to re-login...")
        _session_cookie = None
        _login_qbittorrent()
        
        # Retry the request
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        if _session_cookie and _session_cookie != "logged_in":
            headers['Cookie'] = _session_cookie
            
        response = _http.request(
            'POST',
            url,
            body=data_encoded,
            headers=headers
        )

    if response.status != 200:
        raise Exception(f"Failed to update qBittorrent: HTTP {response.status}")

    logger.info(f"Updated qBittorrent settings: {kwargs}")

###############################################################################
def refresh_qb_port():
    """Main function to refresh qBittorrent port mapping"""
    npc = NatPmpClient(VPN_GW)
    
    try:
        # Get public IP
        public_ip = npc.get_public_address()
        
        # Create TCP port mapping (qBittorrent needs TCP)
        tcp_mapping = npc.create_port_mapping('TCP', internal_port=0, external_port=0, lifetime=3600)
        
        # Create UDP port mapping for the same ports (for DHT)
        udp_mapping = npc.create_port_mapping('UDP', 
                                            internal_port=tcp_mapping['internal_port'], 
                                            external_port=tcp_mapping['external_port'], 
                                            lifetime=3600)
        
        # Update qBittorrent configuration
        update_qbittorrent(
            listen_port=tcp_mapping['internal_port'],
            random_port=False,
            upnp=False,
            natpmp=False  # Disable built-in NAT-PMP since we're handling it
        )
        
        result = {
            'public_ip': public_ip,
            'tcp_mapping': tcp_mapping,
            'udp_mapping': udp_mapping
        }
        
        logger.info(f"Port forwarding successful: {public_ip}:{tcp_mapping['external_port']} -> local:{tcp_mapping['internal_port']}")
        
        return result
        
    finally:
        npc.close()

# Main loop
if __name__ == "__main__":
    while True:
        logger.info("Refreshing qBittorrent port mapping...")
        try:
            result = refresh_qb_port()
            # Sleep for 90% of the lifetime, minimum 30 seconds
            sleep_time = max(int(result['tcp_mapping']['lifetime'] * 0.9), 30)
            logger.info(f"Next refresh in {sleep_time} seconds")
            
        except Exception as e:
            logger.error(f"Port mapping failed: {e}")
            sleep_time = 60  # Retry in 1 minute on error
            
        time.sleep(sleep_time)