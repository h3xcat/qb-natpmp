"""Small NAT-PMP client for Proton VPN's short-lived port mappings."""

import logging
import math
import socket
import struct
import time


logger = logging.getLogger(__name__)


class NatPmpError(Exception):
    def __init__(self, message, error_code=None):
        super().__init__(message)
        self.error_code = error_code


class NatPmpClient:
    def __init__(self, gateway: str, timeout: float = 3.0):
        self.sock = None
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("NAT-PMP timeout must be positive and finite")
        self.gateway = gateway
        self.timeout = timeout
        try:
            # Resolve once, so replies are checked against the address we used.
            self.gateway_address = socket.gethostbyname(gateway)
        except OSError as exc:
            raise NatPmpError(f"Cannot resolve NAT-PMP gateway: {exc}") from exc

    def _send_request(self, request_data, response_length, internal_port=None):
        """Retry a request within one deadline, discarding unrelated replies."""
        if self.sock is None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        expected_opcode = request_data[1] + 128
        destination = (self.gateway_address, 5351)
        started_at = time.monotonic()
        deadline = started_at + self.timeout
        retry_interval = 0.25

        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self.sock.settimeout(remaining)
                self.sock.sendto(request_data, destination)
                attempt_deadline = min(time.monotonic() + retry_interval, deadline)

                while True:
                    remaining = attempt_deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    self.sock.settimeout(remaining)
                    try:
                        # One extra byte distinguishes oversized packets from
                        # valid 16-byte replies instead of silently truncating.
                        response, address = self.sock.recvfrom(17)
                    except socket.timeout:
                        break

                    if address != destination or len(response) != response_length:
                        continue
                    version, opcode, result, _ = struct.unpack("!BBHI", response[:8])
                    if version != 0 or opcode != expected_opcode:
                        continue
                    if internal_port is not None:
                        response_internal = struct.unpack("!H", response[8:10])[0]
                        # Proton assigns an internal port when zero was requested.
                        if internal_port != 0 and response_internal != internal_port:
                            continue
                    if result != 0:
                        raise NatPmpError(f"NAT-PMP error result: {result}", result)
                    return response, started_at

                retry_interval = min(retry_interval * 2, 1.0)
        except OSError as exc:
            raise NatPmpError(f"NAT-PMP communication failed: {exc}") from exc

        raise NatPmpError("NAT-PMP request timed out")

    def get_public_address(self) -> str:
        response, _ = self._send_request(struct.pack("!BB", 0, 0), 12)
        public_ip = socket.inet_ntoa(response[8:12])
        logger.info("Got public IP: %s", public_ip)
        return public_ip

    def create_port_mapping(
        self, protocol: str, internal_port: int = 0, external_port: int = 0,
        lifetime: int = 3600,
    ) -> dict:
        protocol = protocol.upper()
        if protocol not in ("TCP", "UDP"):
            raise ValueError("Protocol must be 'TCP' or 'UDP'")
        if not all(isinstance(port, int) and 0 <= port <= 65535
                   for port in (internal_port, external_port)):
            raise ValueError("Ports must be integers between 0 and 65535")
        if not isinstance(lifetime, int) or not 1 <= lifetime <= 0xFFFFFFFF:
            raise ValueError("Mapping lifetime must be a positive 32-bit integer")

        opcode = 1 if protocol == "UDP" else 2
        request = struct.pack("!BBHHHL", 0, opcode, 0, internal_port, external_port, lifetime)
        response, granted_at = self._send_request(request, 16, internal_port)
        _, _, _, epoch, assigned_internal, assigned_external, assigned_lifetime = struct.unpack(
            "!BBHIHHL", response
        )
        if assigned_internal == 0 or assigned_external == 0 or assigned_lifetime == 0:
            raise NatPmpError("NAT-PMP returned an invalid port mapping grant")

        mapping = {
            "protocol": protocol,
            "internal_port": assigned_internal,
            "external_port": assigned_external,
            "lifetime": assigned_lifetime,
            "epoch": epoch,
            # The first request may have succeeded even if its reply was lost.
            # Measuring from then never overestimates the remaining lease.
            "granted_at": granted_at,
            "expires_at": granted_at + assigned_lifetime,
        }
        logger.info("%s port mapping: %s -> %s (lifetime: %ss)",
                    protocol, assigned_external, assigned_internal, assigned_lifetime)
        return mapping

    def close(self):
        if self.sock is not None:
            self.sock.close()
            self.sock = None

    def __del__(self):
        self.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
