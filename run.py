import logging
import os
import time

from health import clear_health, write_health
from natpmp import NatPmpClient, NatPmpError
from qbittorrent import QbittorrentClient

VPN_GW = os.getenv('VPN_GATEWAY', '10.2.0.1')
QB_URL = os.getenv('QB_URL', 'http://127.0.0.1:9080')
QB_USER = os.getenv('QB_USER', 'admin')
QB_PASS = os.getenv('QB_PASS', 'admin')

logger = logging.getLogger(__name__)
RETRY_INTERVAL = 5.0


def refresh_mappings(gateway):
    """Get matching TCP/UDP grants, keeping their original lease deadlines."""
    with NatPmpClient(gateway) as client:
        public_ip = client.get_public_address()
        tcp = client.create_port_mapping('TCP', lifetime=60)
        udp = client.create_port_mapping(
            'UDP', internal_port=tcp['internal_port'],
            external_port=tcp['external_port'], lifetime=60,
        )

    for key in ('internal_port', 'external_port'):
        if tcp[key] != udp[key]:
            raise NatPmpError(f"TCP and UDP {key} differ: {tcp[key]} != {udp[key]}")

    grants = (tcp, udp)
    expires_at = min(grant['expires_at'] for grant in grants)
    if expires_at <= time.monotonic():
        raise NatPmpError('Port mapping expired before both grants completed')
    return {
        'public_ip': public_ip,
        'listen_port': tcp['internal_port'],
        'external_port': tcp['external_port'],
        'expires_at': expires_at,
        # Start the clock at the request, not after the HTTP update finishes.
        'renew_at': min(grant['granted_at'] + grant['lifetime'] / 2 for grant in grants),
    }


class PortForwarder:
    """Renew VPN leases and retry qBittorrent independently in one bounded loop."""

    def __init__(self, gateway, qbittorrent):
        self.gateway = gateway
        self.qbittorrent = qbittorrent
        self.mapping = None
        self.next_renewal = 0.0
        self.next_sync = 0.0

    @staticmethod
    def invalidate_health():
        try:
            clear_health()
        except OSError:
            logger.exception('Could not remove the health marker')

    def step(self):
        if time.monotonic() >= self.next_renewal:
            try:
                mapping = refresh_mappings(self.gateway)
                # An old successful sync cannot certify a newly assigned port.
                if self.mapping is None or any(
                    mapping[key] != self.mapping[key]
                    for key in ('public_ip', 'listen_port', 'external_port')
                ):
                    self.invalidate_health()
                self.mapping = mapping
                self.next_renewal = mapping['renew_at']
                self.next_sync = time.monotonic()
                logger.info('Renewed TCP/UDP mapping: %s:%s -> local:%s',
                            mapping['public_ip'], mapping['external_port'], mapping['listen_port'])
            except Exception as exc:
                logger.error('Port mapping failed: %s', exc)
                self.mapping = None
                self.invalidate_health()
                self.next_renewal = time.monotonic() + RETRY_INTERVAL

        if self.mapping is not None and time.monotonic() >= self.next_sync:
            # A short lease may already have expired during the NAT requests.
            if time.monotonic() >= self.mapping['expires_at']:
                self.invalidate_health()
                self.next_renewal = time.monotonic()
            else:
                try:
                    self.qbittorrent.update_preferences(
                        listen_port=self.mapping['listen_port'],
                        random_port=False, upnp=False, natpmp=False,
                    )
                    write_health(self.mapping['expires_at'])
                    self.next_sync = self.next_renewal
                    logger.info('Port forwarding and qBittorrent synchronized')
                except Exception as exc:
                    logger.error('qBittorrent synchronization failed: %s', exc)
                    # Preserve the NAT deadline even while the API is unavailable.
                    self.next_sync = time.monotonic() + RETRY_INTERVAL

        deadline = self.next_renewal
        if self.mapping is not None:
            deadline = min(deadline, self.next_sync)
        return max(0.0, deadline - time.monotonic())


def main():
    logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S', level=logging.INFO)
    logger.info('Using VPN gateway: %s; qBittorrent URL: %s', VPN_GW, QB_URL)
    # Never inherit a success marker from a previous process/container start.
    clear_health()
    client = QbittorrentClient(QB_URL, QB_USER, QB_PASS)
    forwarder = PortForwarder(VPN_GW, client)
    try:
        while True:
            delay = forwarder.step()
            time.sleep(max(0.05, delay))
    finally:
        client.close()
        clear_health()


if __name__ == '__main__':
    main()
