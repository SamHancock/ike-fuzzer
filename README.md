# IKEv1 / IKEv2 Client & Fuzzer

Python 3 implementation of IKEv1 and IKEv2 initiator-side exchanges with PSK
authentication, plus a structured protocol fuzzer.

- **IKEv2** (RFC 7296) — full `IKE_SA_INIT` / `IKE_AUTH` exchange
- **IKEv1** (RFC 2408 / RFC 2409) — Phase 1 Main Mode (6-message) and Aggressive Mode (3-message)
- **Fuzzer** — 66 structured mutation cases + configurable random byte-flip rounds

## Project status

| Feature | Status |
|---------|--------|
| IKEv2 IKE_SA_INIT / IKE_AUTH (PSK) | Working |
| IKEv2 AEAD (AES-GCM) | Working |
| IKEv2 ECDH (P-256 / P-384 / P-521) | Working — RFC 5903 §3 encoding (x\|\|y, no 0x04 prefix) |
| IKEv1 Main Mode (6-message) | Working |
| IKEv1 Aggressive Mode (3-message) | Working |
| IKEv1 ECDH (P-521 / group 21) | Working |
| Protocol fuzzer — structured mutations | Working — 66 cases across 6 categories |
| Protocol fuzzer — random byte-flip | Working — reproducible via `--seed` |
| strongSwan Docker test environment | Available — `docker/` subdirectory |

## Files

| File | Purpose |
|------|---------|
| `ike_client.py` | IKEv1 / IKEv2 client — select with `--version 1` or `--version 2` |
| `ike_fuzzer.py` | Protocol fuzzer — structured and random mutations of IKE_SA_INIT |
| `requirements.txt` | Python dependencies |
| `docker/` | strongSwan 5.9 responder for local testing (see below) |

## Setup

```bash
python3 -m venv venv
venv/bin/pip install -r requirements.txt
```

---

## Docker test environment

The `docker/` directory contains a strongSwan 5.9 responder pre-configured for all
supported algorithm combinations, listening on `127.0.0.1:500`.

### Build and run

```bash
cd docker
docker build -t ike-test-swan .
docker run --rm --network host --name swan-test ike-test-swan
```

### Pre-configured connections

| Name | Version | Mode | Proposals |
|------|---------|------|-----------|
| `ikev1-main` | IKEv1 | Main Mode | AES-256-CBC + SHA-1/256/512 + MODP-2048 or ECP-521 |
| `ikev1-agg` | IKEv1 | Aggressive Mode | same as above |
| `ikev2-psk` | IKEv2 | — | AES-256-CBC + SHA-256/1 + MODP-2048; AES-256-GCM + MODP-2048 |
| `ikev2-psk-gcm` | IKEv2 | — | AES-256-GCM + PRF-SHA-256 + MODP-2048 |
| `ikev2-gcm-sha512` | IKEv2 | — | AES-256-GCM + PRF-SHA-512 + ECP-521 |

PSK for all connections: **`secret`**

### Notes

- `interfaces_use = lo` — charon binds to loopback only.
- `i_dont_care_about_security_and_use_aggressive_mode_psk = yes` — required by
  strongSwan ≥ 5.4 to allow Aggressive Mode with PSK (disabled by default due to
  offline dictionary-attack exposure).
- `libstrongswan-standard-plugins` and `libstrongswan-extra-plugins` provide the
  `gcm` and `openssl` plugins needed for AES-GCM and elliptic-curve DH.

---

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

Default configuration against the Docker responder:
```bash
venv/bin/python ike_client.py 127.0.0.1 --psk secret
```

AES-256-GCM / PRF-SHA-512 / P-521:
```bash
venv/bin/python ike_client.py 127.0.0.1 \
    --encr aes-gcm-256 \
    --prf hmac-sha512 \
    --dh-group 21 \
    --psk secret
```

AES-256-CBC / SHA-512 / P-521:
```bash
venv/bin/python ike_client.py 127.0.0.1 \
    --encr aes-cbc-256 \
    --integ hmac-sha512-256 \
    --prf hmac-sha512 \
    --dh-group 21 \
    --psk secret
```

Legacy interop (3DES, SHA-1, MODP-1024):
```bash
venv/bin/python ike_client.py 10.0.0.1 \
    --encr 3des \
    --integ hmac-sha1-96 \
    --prf hmac-sha1 \
    --dh-group 2 \
    --psk "MySecret"
```

Verbose output with hex dumps and key material:
```bash
venv/bin/python ike_client.py 127.0.0.1 --psk secret -v
```

Run built-in crypto self-tests:
```bash
venv/bin/python ike_client.py --self-test
```

### Debugging — verbose output (`-v`)

`-v` enables detailed logging at every stage of the exchange:

```
[IKE_SA_INIT →]  sending 376 bytes to 127.0.0.1:500
  00000000  2a 1c 4f 8e …   (full hex dump of outgoing packet)

[IKE_SA_INIT ←]  received 480 bytes
  00000000  2a 1c 4f 8e …   (full hex dump of incoming packet)

[SA]  selected: ENCR=AES-CBC-256  PRF=HMAC-SHA256  INTEG=HMAC-SHA256-128  DH=14
[KE]  responder public key: a3 f7 …  (256 bytes)
[DH]  shared secret (256 bytes): 3f a0 …

[PRF] SKEYSEED : …
[PRF] SK_d     : …
[PRF] SK_ai    : …   SK_ar: …
[PRF] SK_ei    : …   SK_er: …
[PRF] SK_pi    : …   SK_pr: …

[IKE_AUTH →]  sending 272 bytes (encrypted)
[IKE_AUTH ←]  received 304 bytes — AUTH verified OK
```

Key-derivation steps (SKEYSEED → SK_\* chain), each payload parsed, and the
AUTH verification result are all printed. Without `-v`, only the final
success or failure message is shown.

### IKEv2 protocol overview

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

---

## IKEv1 Client

### Basic usage

```bash
venv/bin/python ike_client.py <host> --version 1 [options]
```

### IKEv1-specific options

```
--version 1               Select IKEv1 (default: 2)
--mode {main,aggressive}  Phase 1 exchange mode (default: main)
--hash ALG                Hash / PRF algorithm (default: sha1)
--encr ALG                Encryption (default: aes-cbc-256)
--dh-group N              DH group (default: 14)
--psk PSK                 Pre-shared key
--lifetime N              SA lifetime in seconds (default: 28800)
--capture-file FILE       Aggressive Mode only: save crack material to FILE
                          (JSON) and FILE.hc (hashcat line, MODP-1024 only).
                          Not written unless this option is given.
--psk-crack FILE WORDLIST Offline PSK crack using a --capture-file JSON.
                          Tests every wordlist line against HASH_I and HASH_R.
                          Works for any DH group. No host connection needed.
```

**Hash algorithms (`--hash`)**

| Value | Algorithm |
|-------|-----------|
| `md5` | HMAC-MD5 |
| `sha1` | HMAC-SHA1 *(default)* |
| `sha256` | HMAC-SHA256 |
| `sha512` | HMAC-SHA512 |

**Encryption (`--encr`)** — IKEv1 supports: `3des`, `aes-cbc-128`, `aes-cbc-256`
(AES-GCM is IKEv2-only)

### Examples

Default IKEv1 Main Mode against the Docker responder:
```bash
venv/bin/python ike_client.py 127.0.0.1 --version 1 --psk secret
```

AES-256 + SHA-256 + DH-14:
```bash
venv/bin/python ike_client.py 127.0.0.1 --version 1 \
    --encr aes-cbc-256 \
    --hash sha256 \
    --dh-group 14 \
    --psk secret
```

AES-256 + SHA-256 + P-521 (ECP-521):
```bash
venv/bin/python ike_client.py 127.0.0.1 --version 1 \
    --encr aes-cbc-256 \
    --hash sha256 \
    --dh-group 21 \
    --psk secret
```

Aggressive Mode:
```bash
venv/bin/python ike_client.py 127.0.0.1 --version 1 \
    --mode aggressive \
    --encr aes-cbc-256 \
    --hash sha256 \
    --dh-group 14 \
    --psk secret
```

Aggressive Mode with PSK crack-material capture:
```bash
venv/bin/python ike_client.py 127.0.0.1 --version 1 \
    --mode aggressive \
    --hash sha1 \
    --dh-group 14 \
    --psk secret \
    --capture-file capture.json
```

### Offline PSK cracking (`--capture-file` + `--psk-crack`)

In IKEv1 Aggressive Mode the responder's HASH_R is transmitted in the
clear, exposing the PSK to offline dictionary attack. `--capture-file FILE`
saves all the material needed to crack it — it is **not** written by
default and only applies to `--mode aggressive`.

Two files are written:

| File | Contents |
|------|----------|
| `FILE` | JSON — all fields, both cracking formulae, and tool metadata |
| `FILE.hc` | hashcat-compatible line (MODP-1024 / group 2 only — see below) |

**Cracking formulae (RFC 2409 §5.1):**
```
SKEYID  = HMAC(PSK,     Ni || Nr)
HASH_I  = HMAC(SKEYID,  g_xi || g_xr || CKY-I || CKY-R || SAi_b || IDii_b)
HASH_R  = HMAC(SKEYID,  g_xr || g_xi || CKY-R || CKY-I || SAi_b || IDir_b)
```
Both HASH_I and HASH_R are stored in the JSON. Either can confirm a
correct PSK candidate.

**JSON fields:**

| Field | Description |
|-------|-------------|
| `g_xi` | Initiator DH public key |
| `g_xr` | Responder DH public key |
| `cky_i` | Initiator cookie (8 bytes) |
| `cky_r` | Responder cookie (8 bytes) |
| `nonce_i` | Initiator nonce Ni |
| `nonce_r` | Responder nonce Nr |
| `sai_b` | SA payload body from message 1 (without generic header) |
| `idii_b` | Initiator ID payload body from message 1 (without generic header) |
| `idir_b` | Responder ID payload body from message 2 (without generic header) |
| `hash_i` | HASH_I computed by the initiator |
| `hash_r` | HASH_R received from the responder (transmitted in the clear) |

#### Cracking with `--psk-crack` (recommended)

The built-in cracker works for **any DH group** and tests each candidate
against both HASH_I and HASH_R:

```bash
venv/bin/python ike_client.py --psk-crack capture.json wordlist.txt
```

Example output:
```
[crack] Target     : 127.0.0.1:500
[crack] Hash alg   : SHA1
[crack] HASH_I     : e23ba5fb334921caa8d3b9bf3df9813658d605da
[crack] HASH_R     : 7ee95c94eed194f2153e70d971276f105aa01fa7
[crack] Wordlist   : wordlist.txt

[crack] PSK FOUND (HASH_I match): 'secret'
[crack] Tested 3 candidates in 0.00s
```

#### Cracking with hashcat (MODP-1024 / group 2 only)

> **hashcat limitation:** hashcat modes 5300 (MD5) and 5400 (SHA1) have
> hardcoded buffer limits based on MODP-1024 (128-byte DH keys). Captures
> using DH group 14 (MODP-2048) or larger will fail with a
> `Salt-length exception`. Use `--psk-crack` instead for those groups.

The `.hc` file is only usable when `--dh-group 2` (MODP-1024) was used.
The 9-field format (verified against hashcat's built-in example hashes):

```
g_xi:g_xr:cky_i:cky_r:sai_b:IDii_b:Ni:Nr:HASH_I
```

| Hash algorithm | hashcat mode | Command |
|----------------|-------------|---------|
| SHA-1 | 5400 | `hashcat -m 5400 capture.json.hc wordlist.txt` |
| MD5 | 5300 | `hashcat -m 5300 capture.json.hc wordlist.txt` |
| SHA-256 / SHA-512 | — | No built-in hashcat mode; use `--psk-crack` |

The JSON `hashcat.usage` field will indicate whether the `.hc` file is
usable for the captured DH group, or instruct you to use `--psk-crack`.

### IKEv1 Phase 1 exchange flow

**Main Mode (6 messages):**
```
Initiator                                Responder
─────────────────────────────────────────────────
Msg 1: HDR + SA                ────────>
                               <──────── Msg 2: HDR + SA (selected)
Msg 3: HDR + KE + Ni           ────────>
                               <──────── Msg 4: HDR + KE + Nr
  [key derivation: SKEYID chain]
Msg 5: HDR* + IDii + HASH_I   ────────>
                               <──────── Msg 6: HDR* + IDir + HASH_R
```

**Aggressive Mode (3 messages):**
```
Initiator                                Responder
─────────────────────────────────────────────────
Msg 1: HDR + SA + KE + Ni + IDii ──────>
                          <────────────── Msg 2: HDR + SA + KE + Nr + IDir + HASH_R
  [key derivation]
Msg 3: HDR* + HASH_I             ──────>
```
*(* = encrypted with the negotiated cipher)*

### IKEv1 key derivation (PSK, RFC 2409 §5.1)

```
SKEYID   = prf(PSK,      Ni | Nr)
SKEYID_d = prf(SKEYID,   g^ir | CKY-I | CKY-R | 0x00)
SKEYID_a = prf(SKEYID,   SKEYID_d | g^ir | CKY-I | CKY-R | 0x01)
SKEYID_e = prf(SKEYID,   SKEYID_a | g^ir | CKY-I | CKY-R | 0x02)

HASH_I = prf(SKEYID, g^xi | g^xr | CKY-I | CKY-R | SAi_b | IDii_b)
HASH_R = prf(SKEYID, g^xr | g^xi | CKY-R | CKY-I | SAi_b | IDir_b)
```
*(prf = HMAC with the negotiated hash algorithm)*

---

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
| `header` | 17 | Exchange type, flags, version, message ID, total-length, SPIi, SPIr |
| `sa` | 13 | Transforms: empty, unknown IDs, DH mismatch, wrong protocol, missing PRF/DH, two proposals, key-length extremes (0 / 65535), duplicates, critical bit |
| `ke` | 8 | DH group field; public key (zeros, 0xFF, empty, 1 byte, half-length, one-byte-short) |
| `nonce` | 5 | Size and content (empty, 1 byte, zeros, all-0xFF, 2 KiB) |
| `payload` | 13 | next_payload pointers, missing SA/KE/Nonce, duplicated payloads, payload order swap (SA/Nonce/KE), unknown type appended, length overflow |
| `truncate` | 10 | Packet truncated at 4, 20, 27, 28, 32, 60, 94, 188, 372, 375 bytes |
| `random` | `--rounds` | 1–4 random byte flips at random offsets (annotated with field names) |

Total structured cases: **66** (before random rounds).

### Reading the output

Verdicts are colour-coded in the terminal:

| Colour | Verdict | Meaning |
|--------|---------|---------|
| Green | `ACCEPTED` | Responder assigned an SPIr — SA offered |
| Cyan | `REJECTED` | Error Notify present, or SPIr=0 with only informational notifies |
| Dark grey | `TIMEOUT` | No response within `--timeout` seconds |
| Yellow | `INTERESTING` | Valid framing but genuinely ambiguous (SPIi mismatch, SPIr=0 with no notifies, wrong exchange type) |
| Red | `MALFORMED` | Response shorter than 28 bytes |

Cases flagged `***` are those where the observed verdict differs from the expected
column — these are written to the `findings` array of the JSON report.

### Random mutation detail

Each random case prints an annotated sub-line per flipped byte showing the
packet offset, field name, original byte, and mutated byte:

```
  67  random  random-000  REJECTED  notify: MULTIPLE_AUTH_SUPPORTED
        [ 33 SA-prop1 reserved]  0x00 → 0xce
        [292 KE pubkey[208]]     0x57 → 0x54
        [374 Nonce data[30]]     0x8b → 0xc4
```

Field names cover every byte in the IKE fixed header and all standard payload
types (SA transforms, KE, Nonce). The same data appears in the `mutations` array
of the JSON report.

### Examples

Full run against the Docker responder, saving results:
```bash
venv/bin/python ike_fuzzer.py 127.0.0.1 \
    --psk secret \
    --rounds 50 \
    --report findings.json
```

Header and SA mutations only, no random rounds:
```bash
venv/bin/python ike_fuzzer.py 127.0.0.1 \
    --psk secret \
    --strategy header,sa \
    --rounds 0
```

GCM base packet with P-521, all strategies:
```bash
venv/bin/python ike_fuzzer.py 127.0.0.1 \
    --encr aes-gcm-256 \
    --prf hmac-sha512 \
    --dh-group 21 \
    --psk secret \
    --rounds 50
```

Reproducible random fuzzing with a fixed seed:
```bash
venv/bin/python ike_fuzzer.py 127.0.0.1 \
    --rounds 100 \
    --seed 42 \
    --report run_seed42.json
```

Structured mutations only, maximum speed:
```bash
venv/bin/python ike_fuzzer.py 127.0.0.1 \
    --strategy header,sa,ke,nonce,payload,truncate \
    --rounds 0 \
    --delay 0
```

### JSON report format

`--report` writes a JSON file with the following top-level structure:

```json
{
  "target":    "127.0.0.1:500",
  "timestamp": "2026-06-05T12:00:00",
  "config":    { "encr": "aes-cbc-256", "prf": "hmac-sha256", "dh_group": 14, … },
  "strategies": ["header", "sa", …],
  "rounds":    100,
  "seed":      1337,
  "summary":   { "total": 166, "accepted": 1, "rejected": 154, "timeout": 11,
                 "interesting_findings": 1 },
  "findings":  [ … ],
  "all":       [ … ]
}
```

Each entry in `all` / `findings`:

```json
{
  "seq":         67,
  "name":        "random-000",
  "category":    "random",
  "description": "Random flip: [33 SA-prop1 reserved] 0x00→0xce, …",
  "pkt_len":     376,
  "mutations": [
    { "offset": 33, "field": "SA-prop1 reserved",
      "original": "0x00", "modified": "0xce" }
  ],
  "expected":    "any",
  "verdict":     "rejected",
  "notify_type": 16390,
  "notes":       "notify: MULTIPLE_AUTH_SUPPORTED",
  "elapsed_ms":  1.23,
  "interesting": false
}
```

### Known finding — strongSwan SPIr leniency

RFC 7296 §2.6 requires the responder SPI (SPIr) in an IKE_SA_INIT *request* to be
all zeros. strongSwan 5.9 accepts the request and completes SA_INIT regardless.
This surfaces as `ACCEPTED` on case `spi-r-nonzero` (header strategy) and on any
random case that flips a byte in `IKE-hdr SPIr[N]` from `0x00` to non-zero. All
other mutations across 166 cases with `--rounds 100` were correctly rejected or
timed out.

---

## Dependencies

- [cryptography](https://cryptography.io/) ≥ 43 — DH/ECDH, AES-CBC, AES-GCM, HMAC
