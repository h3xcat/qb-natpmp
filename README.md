# qb-natpmp

Keeps Proton VPN's TCP/UDP port mappings alive and synchronizes qBittorrent's
listening port. Run the helper in the same network namespace as the VPN and
qBittorrent, with the VPN kill switch already active.

## Configuration

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `VPN_GATEWAY` | `10.2.0.1` | IPv4 NAT-PMP gateway |
| `QB_URL` | `http://127.0.0.1:9080` | qBittorrent Web API URL; set the actual WebUI port |
| `QB_USER` | `admin` | Web API username |
| `QB_PASS` | `admin` | Web API password |
| `QB_NATPMP_HEALTH_FILE` | `/tmp/qb-natpmp-health.json` | Writable, container-local health marker |

The VPN profile must enable NAT-PMP/port forwarding. qBittorrent must be
reachable at `QB_URL`. Successful logins using either HTTP 200/`Ok.` or HTTP 204
are supported; failed credentials remain errors.

## Renewal and recovery

The helper requests 60-second TCP and UDP leases, checks that both protocols
receive the same internal and external ports, and renews halfway through the
shortest granted lease. Deadlines use monotonic time measured from the request,
so API processing time does not extend a lease. This follows the renewal
recommendation in [RFC 6886 section 3.3](https://datatracker.ietf.org/doc/html/rfc6886#section-3.3).

NAT-PMP requests retransmit within a three-second deadline. Replies must come
from the selected gateway on UDP 5351 and match the request. Invalid or unrelated
datagrams cannot extend that deadline. Failed refreshes retry after five seconds.

qBittorrent requests use two-second connection and three-second read timeouts,
with automatic retries and redirects disabled. Failed synchronization retries
after five seconds without moving the next lease renewal deadline. After a
qBittorrent restart, an expired session is authenticated again. The helper
reapplies the port on each successful renewal.

## Health and monitoring

```sh
python3 /opt/app/health.py
```

Exit code 0 means matching TCP/UDP grants were successfully synchronized with
qBittorrent and the earliest lease has not expired. Exit code 1 means startup,
missing/corrupt state, failed mapping, or an expired success marker. The JSON
marker also records `last_success` as a Unix timestamp for diagnostics. It is
written atomically, contains no credentials, and is cleared at process startup.
Keep this file on container-local storage, not a persistent/shared volume.

The image includes a Docker `HEALTHCHECK`. Kubernetes requires an explicit
probe; it does not run the Docker health check. Add this to the **qb-natpmp
container** when deploying a release containing `health.py`:

```yaml
readinessProbe:
  exec:
    command: [python3, /opt/app/health.py]
  periodSeconds: 10
  timeoutSeconds: 3
  failureThreshold: 2
```

A failed readiness probe marks the entire Pod unready, which removes it from
normal Service traffic, including qBittorrent's WebUI. Choose this behavior
intentionally; if the UI must remain available during VPN outages, have your
monitor execute the health command separately instead. A VPN credential expiry
needs operator action, so this lease-health check is not a liveness restart
policy. [Kubernetes probe behavior](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/)

With kube-state-metrics and the readiness probe above, an alert rule can detect
persistent failures:

```yaml
- alert: QbNatpmpUnhealthy
  expr: kube_pod_container_status_ready{container="qb-natpmp"} == 0
  for: 2m
  labels:
    severity: warning
  annotations:
    summary: "qBittorrent port forwarding has not recovered"
    description: "Inspect qb-natpmp logs, VPN connectivity/credential expiry, and qBittorrent API access."
```

Probe and alert configuration belong to the deployment repository; rebuilding
this helper alone does not install them in an existing Kubernetes workload.
The health command checks lease/API synchronization, not an external incoming
connection or the validity period of the VPN account's credential.

## Tests

```sh
python3 -m pip install -r requirements.txt
python3 -m unittest discover -s tests -v
```

Tests cover API compatibility and stalled HTTP connections, lost/malformed
NAT-PMP replies, renewal deadlines during API failures, TCP/UDP consistency,
and health-marker expiry. They do not need a VPN or live qBittorrent.
