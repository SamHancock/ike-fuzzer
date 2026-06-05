# IKEv2 Client & Fuzzer

Python 3 implementation of the IKEv2 initiator-side `IKE_SA_INIT` / `IKE_AUTH`
exchange (RFC 7296) with PSK authentication, plus a structured protocol fuzzer.

## Files

| File | Purpose |
|------|---------|
| `ike_client.py` | IKEv2 client — full IKE_SA_INIT + IKE_AUTH exchange |
| `ike_fuzzer.py` | Protocol fuzzer — structured and random mutations |
| `requirements.txt` | Python dependencies |

## Setup

```bash
python3 -m venv venv
venv/bin/pip install -r requirements.txt
```

## IKEv2 Client

### Basic usage

```bash
venv/bin/python ike_client.py <host> [options]
```

### Options

```
positional:
  host                  Responder IP address or hostname

algorithm selection:
  --encr ALG            Encryption algorithm (default: aes-cbc-256)
  --integ ALG           Integrity algorithm  (default: hmac-sha256-128)
  --prf ALG             PRF algorithm        (default: hmac-sha256)
  --dh-group N          DH group number      (default: 14)

authentication:
  --psk PSK             Pre-shared key (default: secret)
  --id-local ID         Local IKE identity   (default: outbound IP)
  --id-remote ID        Remote IKE identity  (default: host)

network:
  -p, --port PORT       UDP port             (default: 500)
  --timeout SECONDS     Response timeout     (default: 5.0)

output:
  -v, --verbose         Show hex dumps of all packets and crypto operations
  --self-test           Run built-in crypto self-tests and exit
```

### Supported algorithms

**Encryption (`--encr`)**

| Value | Algorithm |
|-------|-----------|
| `3des` | Triple-DES CBC |
| `aes-cbc-128` | AES-128-CBC |
| `aes-cbc-192` | AES-192-CBC |
| `aes-cbc-256` | AES-256-CBC *(default)* |
| `aes-gcm-128` | AES-128-GCM (AEAD) |
| `aes-gcm-192` | AES-192-GCM (AEAD) |
| `aes-gcm-256` | AES-256-GCM (AEAD) |

**Integrity (`--integ`)** — not used with AEAD ciphers

| Value | Algorithm |
|-------|-----------|
| `hmac-md5-96` | HMAC-MD5-96 |
| `hmac-sha1-96` | HMAC-SHA1-96 |
| `hmac-sha256-128` | HMAC-SHA256-128 *(default)* |
| `hmac-sha384-192` | HMAC-SHA384-192 |
| `hmac-sha512-256` | HMAC-SHA512-256 |

**PRF (`--prf`)**

| Value | Algorithm |
|-------|-----------|
| `hmac-md5` | HMAC-MD5 |
| `hmac-sha1` | HMAC-SHA1 |
| `hmac-sha256` | HMAC-SHA256 *(default)* |
| `hmac-sha384` | HMAC-SHA384 |
| `hmac-sha512` | HMAC-SHA512 |

**DH Group (`--dh-group`)**

| Value | Group |
|-------|-------|
| `2` | 1024-bit MODP |
| `5` | 1536-bit MODP |
| `14` | 2048-bit MODP *(default)* |
| `19` | 256-bit EC (P-256) |
| `20` | 384-bit EC (P-384) |
| `21` | 521-bit EC (P-521) |

### Examples

Default configuration (AES-256-CBC, HMAC-SHA256, DH-14):
```bash
venv/bin/python ike_client.py 10.0.0.1 --psk "MySecret"
```

**AES-256 + SHA-512 + P-521 (DH group 21):**
```bash
venv/bin/python ike_client.py 10.0.0.1 \
    --encr aes-cbc-256 \
    --integ hmac-sha512-256 \
    --prf hmac-sha512 \
    --dh-group 21 \
    --psk "MySecret"
```

AES-256-GCM (AEAD — no separate integrity algorithm) with P-384:
```bash
venv/bin/python ike_client.py 10.0.0.1 \
    --encr aes-gcm-256 \
    --prf hmac-sha256 \
    --dh-group 20 \
    --psk "MySecret"
```

Legacy interop (3DES, SHA1, MODP-1024):
```bash
venv/bin/python ike_client.py 10.0.0.1 \
    --encr 3des \
    --integ hmac-sha1-96 \
    --prf hmac-sha1 \
    --dh-group 2 \
    --psk "MySecret"
```

Verbose output with hex dumps:
```bash
venv/bin/python ike_client.py 10.0.0.1 --psk "MySecret" -v
```

Run built-in crypto self-tests:
```bash
venv/bin/python ike_client.py --self-test
```

## IKEv2 Fuzzer

Builds a valid `IKE_SA_INIT` packet and applies structured and random mutations
to probe how a responder handles malformed input.

### Basic usage

```bash
venv/bin/python ike_fuzzer.py <host> [options]
```

### Options

```
positional:
  host                  Responder IP address or hostname

fuzzing:
  --strategy LIST       Comma-separated strategies (default: all)
                          header, sa, ke, nonce, payload, truncate, random
  --rounds N            Random-mutation cases (default: 20; 0 = disable)
  --seed N              RNG seed for reproducibility (default: 1337)
  --delay SECONDS       Delay between sends (default: 0.05)
  --timeout SECONDS     Per-case response timeout (default: 2.0)

base packet:
  --encr / --prf / --integ / --dh-group / --psk
                        Algorithm options for the base valid packet
                        (same choices as ike_client.py)

output:
  --report FILE         Save JSON results to FILE
  -v, --verbose         Hex-dump each response
  --no-color            Disable ANSI colour output
```

### Mutation strategies

| Strategy | Cases | What is mutated |
|----------|------:|-----------------|
| `header` | 17 | Exchange type, flags, version, message ID, length field, SPIi, SPIr |
| `sa` | 8 | SA transforms: empty, unknown IDs, DH mismatch, wrong protocol, duplicates, critical bit |
| `ke` | 6 | KE DH group field, public key (zeros / 0xFF / empty / 1 byte) |
| `nonce` | 4 | Nonce size (empty / 1 byte / all-zeros / 2 KiB) |
| `payload` | 6 | next_payload pointers, unknown payload type appended, no payloads, length overflow |
| `truncate` | 10 | Packet truncated to 4, 20, 27, 28, 32, 60, 94, 188, 372, 375 bytes |
| `random` | `--rounds` | 1–4 random byte flips at random offsets |

### Examples

Full run against a target, saving results:
```bash
venv/bin/python ike_fuzzer.py 10.0.0.1 \
    --psk "MySecret" \
    --rounds 50 \
    --report findings.json
```

**AES-256 + SHA-512 + P-521 base packet, header and SA mutations only:**
```bash
venv/bin/python ike_fuzzer.py 10.0.0.1 \
    --encr aes-cbc-256 \
    --integ hmac-sha512-256 \
    --prf hmac-sha512 \
    --dh-group 21 \
    --psk "MySecret" \
    --strategy header,sa \
    --rounds 0
```

Structured mutations only (no random), no delay:
```bash
venv/bin/python ike_fuzzer.py 10.0.0.1 \
    --strategy header,sa,ke,nonce,payload,truncate \
    --rounds 0 \
    --delay 0
```

Reproducible random fuzzing with a fixed seed:
```bash
venv/bin/python ike_fuzzer.py 10.0.0.1 \
    --rounds 100 \
    --seed 42 \
    --report run_seed42.json
```

### Verdict meanings

| Verdict | Meaning |
|---------|---------|
| `ACCEPTED` | Responder assigned an SPIr with no error notify — SA offered |
| `REJECTED` | Responder returned an error Notify (e.g. `NO_PROPOSAL_CHOSEN`) |
| `TIMEOUT` | No response within `--timeout` seconds |
| `INTERESTING` | Response has unexpected framing (wrong exchange type, SPIi mismatch, …) |
| `MALFORMED` | Response shorter than 28 bytes |

Cases where the verdict differs from the expected column are flagged with `***`
in the output and written to the `findings` array of the JSON report.

## Protocol overview

```
Initiator                                Responder
─────────────────────────────────────────────────
IKE_SA_INIT  ──────────────────────────>
  SA (ENCR + PRF + INTEG + DH)
  KE (DH public key)
  Ni (nonce)

                <──────────────────────── IKE_SA_INIT
                  SA (selected algorithms)
                  KE (responder DH public key)
                  Nr (nonce)

  [key derivation: SKEYSEED → SK_d, SK_ai/ar, SK_ei/er, SK_pi/pr]

IKE_AUTH  ─────────────────────────────>
  SK { IDi, AUTH, SAi2, TSi, TSr }

                <──────────────────────── IKE_AUTH
                  SK { IDr, AUTH, SAr2, TSi, TSr }
```

Authentication uses PSK (RFC 7296 §2.15):
```
AUTH = prf( prf(PSK, "Key Pad for IKEv2"), signed_octets )
```

## Dependencies

- [scapy](https://scapy.net/) ≥ 2.7 — IKEv2 packet constants and field definitions
- [cryptography](https://cryptography.io/) ≥ 43 — DH/ECDH, AES-CBC, AES-GCM, HMAC
