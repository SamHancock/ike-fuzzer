# SoftEther VPN IPSec test container

Runs SoftEther VPN Server v4.44 on the host network with L2TP/IPSec (IKEv1)
and PSK authentication. Unlike strongSwan, SoftEther's IKE implementation is
entirely userspace — no kernel IPSec modules or special capabilities required.

## Build & run

```bash
cd docker/softether
docker build -t ike-test-softether .
docker run --rm --network host --name softether-test ike-test-softether
```

Build takes a few minutes (compiles SoftEther from source).

## Configuration

| Setting | Default | Override |
|---------|---------|----------|
| IPSec PSK | `secret` | `SE_PSK=…` env var |
| VPN user | `test` | `SE_USER=…` env var |
| User password | `secret` | `SE_PASS=…` env var |
| VPN hub | `VPN` | `SE_HUB=…` env var |

```bash
docker run --rm --network host \
    -e SE_PSK=mypassphrase \
    ike-test-softether
```

## Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 500 | UDP | IKE Phase 1 |
| 4500 | UDP | IKE NAT Traversal |
| 1701 | UDP | L2TP (after IPSec is up) |
| 443 | TCP | SoftEther management (internal) |

> **Note:** SoftEther binds its IKE daemon to `0.0.0.0:500` (no per-interface
> binding), so the container uses host networking. Restrict access with a
> firewall rule if running on a shared host.

## Testing with ike_client.py

SoftEther implements **IKEv1 only** (no IKEv2).

**Verified working combinations (v4.44):**

| Encryption | Hash | DH group | Main Mode | Aggressive Mode |
|------------|------|----------|-----------|-----------------|
| AES-256-CBC | SHA-1 | 14 (MODP-2048) | ✓ | ✓ |
| AES-256-CBC | SHA-256 | 14 (MODP-2048) | ✓ | ✓ |
| AES-128-CBC | SHA-1 | 14 (MODP-2048) | ✓ | ✓ |
| 3DES | SHA-1 | 14 (MODP-2048) | ✓ | ✓ |
| AES-256-CBC | SHA-1 | 2 (MODP-1024) | ✓ | ✓ |
| 3DES | SHA-1 | 2 (MODP-1024) | ✗ rejected | ✗ rejected |

> **Note:** SoftEther 4.44 rejects the combination of 3DES + MODP-1024 (group 2).
> Each algorithm works individually with group 14; group 2 works with AES but not 3DES.

```bash
# Main Mode
python ike_client.py 127.0.0.1 --version 1 --mode main \
    --encr aes-cbc-256 --hash sha1 --dh-group 14 --psk secret

# Aggressive Mode
python ike_client.py 127.0.0.1 --version 1 --mode aggressive \
    --encr aes-cbc-256 --hash sha1 --dh-group 14 --psk secret

# Aggressive Mode with PSK crack-material capture
python ike_client.py 127.0.0.1 --version 1 --mode aggressive \
    --encr aes-cbc-256 --hash sha1 --dh-group 14 --psk secret \
    --capture-file softether_capture.json
```

## Fuzzing

```bash
# IKEv1 Main Mode
python ike_fuzzer.py 127.0.0.1 --ike-version 1 --mode main \
    --v1-encr aes-cbc-256 --hash sha1 --dh-group 14 --psk secret

# IKEv1 Aggressive Mode
python ike_fuzzer.py 127.0.0.1 --ike-version 1 --mode aggressive \
    --v1-encr aes-cbc-256 --hash sha1 --dh-group 14 --psk secret \
    --rounds 50 --report softether_findings.json
```

## Notes

- SoftEther does not support IKEv2, ECDH groups (19/20/21), or AES-GCM.
- The combination of 3DES + DH group 2 (MODP-1024) is rejected; each works individually with other groups.
- SoftEther's IKEv1 parser is highly permissive — see the fuzzing findings in the main README.
- Phase 1 completes successfully; Phase 2 / L2TP are not exercised by ike_client.py.
- The management password is set to `admin` at startup and is only needed for
  internal administration via `vpncmd`.
