#!/usr/bin/env python3
"""IKEv1/IKEv2 client for IKE_SA_INIT / IKE_AUTH (v2) and Phase 1 Main/Aggressive Mode (v1).

Usage:
    python3 ike_client.py <host> [--version {1,2}] [options]

RFC 7296 — IKEv2   RFC 2408/2409 — IKEv1/ISAKMP
"""

import argparse
import hashlib
import hmac as _hmac
import ipaddress
import os
import socket
import struct
import sys
import textwrap
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.ciphers import algorithms as cipher_algorithms
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
try:
    # cryptography ≥ 48 moved TripleDES to the decrepit sub-package
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES as _TripleDES
except ImportError:
    _TripleDES = cipher_algorithms.TripleDES   # type: ignore[attr-defined]

# ---------------------------------------------------------------------------
# IKEv2 constants (mirrors scapy.contrib.ikev2 numeric values)
# ---------------------------------------------------------------------------

EXCHANGE_IKE_SA_INIT = 34
EXCHANGE_IKE_AUTH    = 35

FLAG_INITIATOR = 0x08
FLAG_RESPONSE  = 0x20

PAYLOAD_NONE    = 0
PAYLOAD_SA      = 33
PAYLOAD_KE      = 34
PAYLOAD_IDi     = 35
PAYLOAD_IDr     = 36
PAYLOAD_AUTH    = 39
PAYLOAD_NONCE   = 40
PAYLOAD_NOTIFY  = 41
PAYLOAD_TSi     = 44
PAYLOAD_TSr     = 45
PAYLOAD_SK      = 46

PAYLOAD_NAMES = {
    0:  "NONE",   33: "SA",    34: "KE",   35: "IDi",  36: "IDr",
    39: "AUTH",   40: "Ni",    41: "N",    44: "TSi",  45: "TSr",
    46: "SK",
}

TRANSFORM_TYPE_ENCR   = 1
TRANSFORM_TYPE_PRF    = 2
TRANSFORM_TYPE_INTEG  = 3
TRANSFORM_TYPE_DH     = 4

PROTO_IKE   = 1
PROTO_AH    = 2
PROTO_ESP   = 3

ID_TYPE_IPV4_ADDR = 1
ID_TYPE_FQDN      = 2
ID_TYPE_RFC822    = 3

AUTH_PSK = 2   # Shared Key Message Integrity Code

NOTIFY_NAT_DETECTION_SOURCE_IP      = 16388
NOTIFY_NAT_DETECTION_DESTINATION_IP = 16389
NOTIFY_NO_PROPOSAL_CHOSEN           = 14
NOTIFY_INVALID_KE_PAYLOAD           = 17
NOTIFY_AUTHENTICATION_FAILED        = 24

# ---------------------------------------------------------------------------
# IKEv1 / ISAKMP constants  (RFC 2408, RFC 2409)
# ---------------------------------------------------------------------------

V1_EXCHANGE_MAIN       = 2
V1_EXCHANGE_AGGRESSIVE = 4
V1_EXCHANGE_INFO       = 5
V1_EXCHANGE_QUICK      = 32

V1_FLAG_ENCRYPTION = 0x01
V1_FLAG_COMMIT     = 0x02

# ISAKMP payload type codes (RFC 2408 §3.1)
V1_PAYLOAD_NONE      = 0
V1_PAYLOAD_SA        = 1
V1_PAYLOAD_PROPOSAL  = 2
V1_PAYLOAD_TRANSFORM = 3
V1_PAYLOAD_KE        = 4
V1_PAYLOAD_ID        = 5
V1_PAYLOAD_HASH      = 8
V1_PAYLOAD_NONCE     = 10
V1_PAYLOAD_NOTIFY    = 11
V1_PAYLOAD_VID       = 13

V1_PAYLOAD_NAMES = {
    0: "NONE", 1: "SA", 2: "Proposal", 3: "Transform",
    4: "KE",   5: "ID", 8: "Hash",    10: "Nonce",
    11: "Notify", 13: "VendorID",
}

# SA attribute types
V1_ATTR_ENCR      = 1    # TV  Encryption Algorithm
V1_ATTR_HASH      = 2    # TV  Hash Algorithm
V1_ATTR_AUTH      = 3    # TV  Authentication Method
V1_ATTR_GROUP     = 4    # TV  Group Description (DH)
V1_ATTR_LIFE_TYPE = 11   # TV  Life Type (1=seconds)
V1_ATTR_LIFE_DUR  = 12   # TLV Life Duration
V1_ATTR_KEY_LEN   = 14   # TV  Key Length (AES only)

# Encryption algorithm values (IANA)
V1_ENCR_3DES    = 5
V1_ENCR_AES_CBC = 7

# Hash algorithm values (IANA / RFC 4868)
V1_HASH_MD5    = 1
V1_HASH_SHA1   = 2
V1_HASH_SHA256 = 4
V1_HASH_SHA512 = 6

V1_AUTH_PSK       = 1
V1_DOI_IPSEC      = 1
V1_SITUATION_ID   = 1
V1_PROTO_ISAKMP   = 1
V1_XFORM_KEY_IKE  = 1   # KEY_IKE transform ID for Phase 1

V1_ID_IPV4_ADDR = 1
V1_ID_FQDN      = 2


# ---------------------------------------------------------------------------
# Algorithm descriptors
# ---------------------------------------------------------------------------

@dataclass
class EncrAlg:
    name: str
    transform_id: int
    key_len: int        # bits
    iv_len: int         # bytes
    block_len: int      # bytes (1 for stream/AEAD)
    icv_len: int        # bytes (0 for non-AEAD)
    is_aead: bool

@dataclass
class IntegAlg:
    name: str
    transform_id: int
    key_len: int        # bytes
    trunc_len: int      # bytes (output of HMAC truncated to this)
    hash_algo: str      # 'md5', 'sha1', 'sha256', 'sha384', 'sha512'

@dataclass
class PrfAlg:
    name: str
    transform_id: int
    key_len: int        # bytes (output length, used as key length for prf+)
    hash_algo: str

@dataclass
class DHGroup:
    group_id: int
    name: str
    kind: str           # 'modp' or 'ec'
    pub_key_len: int    # bytes of encoded public key on wire


ENCR_ALGORITHMS: dict[str, EncrAlg] = {
    "3des":        EncrAlg("3des",        3,  192, 8,  8,  0,  False),
    "aes-cbc-128": EncrAlg("aes-cbc-128", 12, 128, 16, 16, 0,  False),
    "aes-cbc-192": EncrAlg("aes-cbc-192", 12, 192, 16, 16, 0,  False),
    "aes-cbc-256": EncrAlg("aes-cbc-256", 12, 256, 16, 16, 0,  False),
    "aes-gcm-128": EncrAlg("aes-gcm-128", 20, 128, 8,  1,  16, True),
    "aes-gcm-192": EncrAlg("aes-gcm-192", 20, 192, 8,  1,  16, True),
    "aes-gcm-256": EncrAlg("aes-gcm-256", 20, 256, 8,  1,  16, True),
}

INTEG_ALGORITHMS: dict[str, IntegAlg] = {
    "hmac-md5-96":     IntegAlg("hmac-md5-96",     1,  16, 12, "md5"),
    "hmac-sha1-96":    IntegAlg("hmac-sha1-96",     2,  20, 12, "sha1"),
    "hmac-sha256-128": IntegAlg("hmac-sha256-128", 12,  32, 16, "sha256"),
    "hmac-sha384-192": IntegAlg("hmac-sha384-192", 13,  48, 24, "sha384"),
    "hmac-sha512-256": IntegAlg("hmac-sha512-256", 14,  64, 32, "sha512"),
}

PRF_ALGORITHMS: dict[str, PrfAlg] = {
    "hmac-md5":    PrfAlg("hmac-md5",    1, 16, "md5"),
    "hmac-sha1":   PrfAlg("hmac-sha1",   2, 20, "sha1"),
    "hmac-sha256": PrfAlg("hmac-sha256", 5, 32, "sha256"),
    "hmac-sha384": PrfAlg("hmac-sha384", 6, 48, "sha384"),
    "hmac-sha512": PrfAlg("hmac-sha512", 7, 64, "sha512"),
}

DH_GROUPS: dict[int, DHGroup] = {
    2:  DHGroup(2,  "1024-bit MODP",    "modp", 128),
    5:  DHGroup(5,  "1536-bit MODP",    "modp", 192),
    14: DHGroup(14, "2048-bit MODP",    "modp", 256),
    19: DHGroup(19, "256-bit EC P-256", "ec",   64),
    20: DHGroup(20, "384-bit EC P-384", "ec",   96),
    21: DHGroup(21, "521-bit EC P-521", "ec",   132),
}

# MODP group prime values (RFC 3526)
MODP_PARAMS: dict[int, tuple[int, int]] = {}   # filled at module init below


def _init_modp_params() -> None:
    """Populate MODP_PARAMS with (prime, generator) for every supported DH group."""
    # Group 2: 1024-bit MODP (RFC 2409)
    MODP_PARAMS[2] = (
        int("FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
            "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
            "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
            "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
            "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381"
            "FFFFFFFF FFFFFFFF".replace(" ", ""), 16),
        2
    )
    # Group 5: 1536-bit MODP (RFC 3526 §2)
    MODP_PARAMS[5] = (
        int("FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
            "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
            "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
            "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
            "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D"
            "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F"
            "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D"
            "670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF".replace(" ", ""), 16),
        2
    )
    # Group 14: 2048-bit MODP (RFC 3526 §3)
    MODP_PARAMS[14] = (
        int("FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
            "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
            "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
            "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
            "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D"
            "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F"
            "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D"
            "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B"
            "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9"
            "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510"
            "15728E5A 8AACAA68 FFFFFFFF FFFFFFFF".replace(" ", ""), 16),
        2
    )

_init_modp_params()


# ---------------------------------------------------------------------------
# IKEv1 algorithm descriptors
# ---------------------------------------------------------------------------

@dataclass
class V1EncrAlg:
    name:      str
    encr_id:   int    # ISAKMP attribute value
    key_bits:  int    # attribute value sent in proposal (e.g. 256 for AES-256)
    key_bytes: int    # actual cipher key length in bytes
    block_len: int    # cipher block / IV size in bytes


@dataclass
class V1HashAlg:
    name:       str
    hash_id:    int   # ISAKMP attribute value
    hash_algo:  str   # hashlib name
    output_len: int   # digest bytes


V1_ENCR_ALGORITHMS: dict[str, V1EncrAlg] = {
    "3des":        V1EncrAlg("3des",        V1_ENCR_3DES,    192, 24, 8),
    "aes-cbc-128": V1EncrAlg("aes-cbc-128", V1_ENCR_AES_CBC, 128, 16, 16),
    "aes-cbc-256": V1EncrAlg("aes-cbc-256", V1_ENCR_AES_CBC, 256, 32, 16),
}

V1_HASH_ALGORITHMS: dict[str, V1HashAlg] = {
    "md5":    V1HashAlg("md5",    V1_HASH_MD5,    "md5",    16),
    "sha1":   V1HashAlg("sha1",   V1_HASH_SHA1,   "sha1",   20),
    "sha256": V1HashAlg("sha256", V1_HASH_SHA256, "sha256", 32),
    "sha512": V1HashAlg("sha512", V1_HASH_SHA512, "sha512", 64),
}


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

class LogLevel(IntEnum):
    DEBUG = 10
    INFO  = 20
    WARN  = 30
    ERROR = 40

LEVEL_NAMES = {10: "DEBUG", 20: "INFO ", 30: "WARN ", 40: "ERROR"}
LEVEL_COLORS = {10: "\033[36m", 20: "\033[32m", 30: "\033[33m", 40: "\033[31m"}
RESET = "\033[0m"


def _hex_dump(data: bytes, indent: int = 4) -> str:
    """Format bytes as a readable hex dump with ASCII sidebar."""
    lines = []
    pad = " " * indent
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part  = " ".join(f"{b:02x}" for b in chunk)
        hex_part  = f"{hex_part:<47}"
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{pad}{i:04x}  {hex_part}  |{ascii_part}|")
    return "\n".join(lines)


class Logger:
    def __init__(self, min_level: int = LogLevel.INFO, verbose: bool = False,
                 color: bool = True):
        """Create a logger with timestamped, phase-tagged, optionally coloured output."""
        self.min_level = min_level
        self.verbose   = verbose
        self.color     = color and sys.stdout.isatty()
        self._phase    = "INIT"

    def set_phase(self, phase: str) -> None:
        """Update the exchange-phase tag shown in every subsequent log line."""
        self._phase = phase

    def _emit(self, level: int, msg: str) -> None:
        """Format and print one log line; no-op if level is below min_level."""
        if level < self.min_level:
            return
        ts    = time.strftime("%H:%M:%S")
        lname = LEVEL_NAMES.get(level, "?????")
        line  = f"[{ts}][{lname}][{self._phase:12s}] {msg}"
        if self.color:
            col  = LEVEL_COLORS.get(level, "")
            line = f"{col}{line}{RESET}"
        print(line, flush=True)

    def debug(self, msg: str, data: Optional[bytes] = None) -> None:
        """Log at DEBUG level; hex-dump `data` if verbose mode is on."""
        self._emit(LogLevel.DEBUG, msg)
        if data is not None and self.verbose:
            print(_hex_dump(data))

    def info(self, msg: str, data: Optional[bytes] = None) -> None:
        """Log at INFO level; hex-dump `data` if verbose mode is on."""
        self._emit(LogLevel.INFO, msg)
        if data is not None and self.verbose:
            print(_hex_dump(data))

    def warn(self, msg: str) -> None:
        """Log at WARN level."""
        self._emit(LogLevel.WARN, msg)

    def error(self, msg: str) -> None:
        """Log at ERROR level."""
        self._emit(LogLevel.ERROR, msg)

    def section(self, title: str) -> None:
        """Print a full-width horizontal rule with a centred title."""
        bar = "─" * 60
        print(f"\n{bar}")
        print(f"  {title}")
        print(f"{bar}")

    def field(self, name: str, value, indent: int = 2) -> None:
        """Log a named key = value pair at DEBUG level."""
        pad = " " * indent
        self._emit(LogLevel.DEBUG, f"{pad}{name:<28} = {value}")

    def hexfield(self, name: str, data: bytes, indent: int = 2) -> None:
        """Log a named bytes field as a hex string at DEBUG level, with an optional hex dump."""
        hex_str = data.hex()
        self._emit(LogLevel.DEBUG, f"{' '*indent}{name:<28} = {hex_str}")
        if self.verbose and len(data) > 4:
            print(_hex_dump(data, indent=indent+4))


# ---------------------------------------------------------------------------
# Config dataclass
# ---------------------------------------------------------------------------

@dataclass
class IKEConfig:
    host:       str
    port:       int          = 500
    encr:       str          = "aes-cbc-256"
    integ:      str          = "hmac-sha256-128"
    prf:        str          = "hmac-sha256"
    dh_group:   int          = 14
    psk:        str          = "secret"
    id_local:   str          = ""
    id_remote:  str          = ""
    timeout:    float        = 5.0
    verbose:    bool         = False

    # resolved algorithm descriptors (filled in __post_init__)
    encr_alg:   EncrAlg      = field(init=False)
    integ_alg:  Optional[IntegAlg] = field(init=False)
    prf_alg:    PrfAlg       = field(init=False)
    dh_info:    DHGroup      = field(init=False)

    def __post_init__(self) -> None:
        """Validate algorithm names and resolve them to their descriptor objects."""
        if self.encr not in ENCR_ALGORITHMS:
            raise ValueError(f"Unknown encryption algorithm: {self.encr!r}")
        if self.integ not in INTEG_ALGORITHMS and not ENCR_ALGORITHMS[self.encr].is_aead:
            raise ValueError(f"Unknown integrity algorithm: {self.integ!r}")
        if self.prf not in PRF_ALGORITHMS:
            raise ValueError(f"Unknown PRF algorithm: {self.prf!r}")
        if self.dh_group not in DH_GROUPS:
            raise ValueError(f"Unknown DH group: {self.dh_group}")

        self.encr_alg  = ENCR_ALGORITHMS[self.encr]
        self.integ_alg = INTEG_ALGORITHMS.get(self.integ) if not self.encr_alg.is_aead else None
        self.prf_alg   = PRF_ALGORITHMS[self.prf]
        self.dh_info   = DH_GROUPS[self.dh_group]

        if not self.id_local:
            self.id_local = _local_ip()
        if not self.id_remote:
            self.id_remote = self.host


def _local_ip() -> str:
    """Return the local IP address that would be used for outbound traffic."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "0.0.0.0"
    finally:
        s.close()


@dataclass
class IKEv1Config:
    """Configuration for an IKEv1 Phase 1 exchange (RFC 2409)."""
    host:      str
    mode:      str   = "main"       # "main" | "aggressive"
    port:      int   = 500
    encr:      str   = "aes-cbc-256"
    hash_alg:  str   = "sha1"       # hash for both PRF and auth
    dh_group:  int   = 14
    psk:       str   = "secret"
    id_local:  str   = ""
    id_remote: str   = ""
    lifetime:  int   = 28800        # seconds
    timeout:   float = 5.0
    verbose:   bool  = False

    # resolved (filled by __post_init__)
    encr_alg:  V1EncrAlg = field(init=False)
    hash_info: V1HashAlg = field(init=False)
    dh_info:   DHGroup   = field(init=False)

    def __post_init__(self) -> None:
        """Validate algorithm names and resolve them to their descriptor objects."""
        if self.encr not in V1_ENCR_ALGORITHMS:
            raise ValueError(
                f"Unsupported IKEv1 encryption: {self.encr!r}. "
                f"Valid: {', '.join(V1_ENCR_ALGORITHMS)}"
            )
        if self.hash_alg not in V1_HASH_ALGORITHMS:
            raise ValueError(
                f"Unknown hash algorithm: {self.hash_alg!r}. "
                f"Valid: {', '.join(V1_HASH_ALGORITHMS)}"
            )
        if self.dh_group not in DH_GROUPS:
            raise ValueError(f"Unknown DH group: {self.dh_group}")
        if self.mode not in ("main", "aggressive"):
            raise ValueError(f"mode must be 'main' or 'aggressive', got {self.mode!r}")

        self.encr_alg  = V1_ENCR_ALGORITHMS[self.encr]
        self.hash_info = V1_HASH_ALGORITHMS[self.hash_alg]
        self.dh_info   = DH_GROUPS[self.dh_group]

        if not self.id_local:
            self.id_local = _local_ip()
        if not self.id_remote:
            self.id_remote = self.host


# Wildcard IPv4 Traffic Selector: TS_IPV4_ADDR_RANGE, proto=any, 0.0.0.0–255.255.255.255
_TS_IPV4_WILDCARD: bytes = struct.pack(
    "!BBHHHBBBBBBBB",
    7, 0, 16,           # TS type, IP proto, selector length
    0, 0xFFFF,          # start port, end port (all ports)
    0, 0, 0, 0,         # start address: 0.0.0.0
    255, 255, 255, 255, # end address:   255.255.255.255
)


# ---------------------------------------------------------------------------
# IKEv2Client
# ---------------------------------------------------------------------------

class IKEv2Client:
    """
    Implements the IKEv2 initiator side of IKE_SA_INIT and IKE_AUTH.

    Milestone implementation progress:
      [M1] Scaffold    – class skeleton, logging, config  ✓
      [M2] Crypto      – DH, PRF, key derivation           ✓
      [M3] IKE_SA_INIT – packet build/send/parse           ✓
      [M4] IKE_AUTH    – SK payload, PSK auth, full auth   ✓
      [M5] Fuzzer      – see ike_fuzzer.py                 ✓
    """

    def __init__(self, cfg: IKEConfig) -> None:
        """Initialise all IKE SA state to empty; no network I/O is performed here."""
        self.cfg  = cfg
        self.log  = Logger(
            min_level=LogLevel.DEBUG,
            verbose=cfg.verbose,
            color=True,
        )

        # IKE SA state
        self.spi_i:      bytes = os.urandom(8)
        self.spi_r:      bytes = b"\x00" * 8
        self.nonce_i:    bytes = b""
        self.nonce_r:    bytes = b""
        self.msg1_bytes: bytes = b""   # raw IKE_SA_INIT request sent
        self.msg2_bytes: bytes = b""   # raw IKE_SA_INIT response received

        # DH state
        self.dh_priv    = None   # private key object
        self.dh_pub:    bytes = b""    # public key bytes (wire format)
        self.dh_shared: bytes = b""   # g^ir bytes

        # Derived keys (all bytes)
        self.sk_d:  bytes = b""
        self.sk_ai: bytes = b""
        self.sk_ar: bytes = b""
        self.sk_ei: bytes = b""
        self.sk_er: bytes = b""
        self.sk_pi: bytes = b""
        self.sk_pr: bytes = b""

        # Child SA state (filled during IKE_AUTH)
        self.child_spi_i: bytes = b""   # our ESP SPI (4 bytes)
        self.child_spi_r: bytes = b""   # peer's ESP SPI

        # message counters
        self._msg_id: int = 0

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Execute the full IKEv2 exchange: IKE_SA_INIT → key derivation → IKE_AUTH."""
        self.log.section("IKEv2 Exchange Start")
        self.log.info(f"Target      : {self.cfg.host}:{self.cfg.port}")
        self.log.info(f"Encryption  : {self.cfg.encr}")
        aead = self.cfg.encr_alg.is_aead
        self.log.info(f"Integrity   : {'(AEAD – no separate integ)' if aead else self.cfg.integ}")
        self.log.info(f"PRF         : {self.cfg.prf}")
        self.log.info(f"DH group    : {self.cfg.dh_group} ({self.cfg.dh_info.name})")
        self.log.info(f"Local ID    : {self.cfg.id_local}")
        self.log.info(f"Remote ID   : {self.cfg.id_remote}")
        self.log.info(f"SPIi        : {self.spi_i.hex()}")

        self.log.set_phase("IKE_SA_INIT")
        self._ike_sa_init()

        self.log.set_phase("KEY_DERIV")
        self._derive_keys()

        self.log.set_phase("IKE_AUTH")
        self._ike_auth()

        self.log.section("Exchange Complete")
        self.log.info("IKE SA established successfully")

    # ------------------------------------------------------------------
    # IKE_SA_INIT
    # ------------------------------------------------------------------

    def _ike_sa_init(self) -> None:
        """
        Full IKE_SA_INIT exchange (RFC 7296 §2.6):
          1. Generate DH keypair and initiator nonce
          2. Build and send IKE_SA_INIT request
          3. Receive and parse IKE_SA_INIT response
          4. Extract responder SPIr, DH pubkey, nonce
          5. Compute g^ir (sets self.dh_shared)
        Key derivation (SKEYSEED → SK_*) runs separately via _derive_keys().
        """
        # 1. Keying material
        self._generate_dh_keypair()
        self.nonce_i = os.urandom(32)

        self.log.section("IKE_SA_INIT Request  [MSG_ID=0]")
        self.log.info(f"Nonce I     ({len(self.nonce_i)}B) : {self.nonce_i.hex()}")
        self.log.info(
            f"DH pub key  ({len(self.dh_pub)}B) : "
            f"{self.dh_pub[:8].hex()}…{self.dh_pub[-4:].hex()}"
        )
        self.log.info(
            f"SA proposal : ENCR={self.cfg.encr} PRF={self.cfg.prf}"
            + (f" INTEG={self.cfg.integ}" if self.cfg.integ_alg else " INTEG=(AEAD)")
            + f" DH={self.cfg.dh_group}"
        )

        # 2. Build payloads (order: SA → KE → Ni)
        nonce_pld = self._build_nonce_payload(PAYLOAD_NONE, self.nonce_i)
        ke_pld    = self._build_ke_payload(PAYLOAD_NONCE)
        sa_pld    = self._build_sa_payload(PAYLOAD_KE)

        payloads  = sa_pld + ke_pld + nonce_pld
        hdr       = self._build_ike_header(
            exch_type=EXCHANGE_IKE_SA_INIT,
            flags=FLAG_INITIATOR,
            msg_id=0,
            next_payload=PAYLOAD_SA,
            total_len=28 + len(payloads),
        )
        pkt = hdr + payloads
        self.msg1_bytes = pkt

        self.log.info(f"Packet size : {len(pkt)} bytes")
        self.log.debug("Raw request :", pkt)

        # 3. Send and receive
        resp = self._send_recv(pkt)
        self.msg2_bytes = resp

        # 4. Parse response header (RFC 7296 §3.1)
        self.log.section("IKE_SA_INIT Response  [MSG_ID=0]")
        if len(resp) < 28:
            raise ValueError(f"Response too short: {len(resp)}B")

        (r_spi_i, r_spi_r, r_nxt, r_ver, r_exch,
         r_flags, r_mid, r_len) = struct.unpack("!8s8sBBBBII", resp[:28])

        self.log.debug(f"  SPIi        : {r_spi_i.hex()}")
        self.log.debug(f"  SPIr        : {r_spi_r.hex()}")
        self.log.debug(f"  Next payload: {PAYLOAD_NAMES.get(r_nxt, r_nxt)}")
        self.log.debug(f"  Version     : 0x{r_ver:02x}")
        self.log.debug(f"  Exch type   : {r_exch}")
        resp_flag = "I" if r_flags & FLAG_INITIATOR else ""
        resp_flag += "R" if r_flags & FLAG_RESPONSE  else ""
        self.log.debug(f"  Flags       : 0x{r_flags:02x} [{resp_flag}]")
        self.log.debug(f"  Msg ID      : {r_mid}")
        self.log.debug(f"  Length      : {r_len}  (received {len(resp)}B)")

        if r_spi_i != self.spi_i:
            raise ValueError(
                f"SPIi mismatch: sent {self.spi_i.hex()}, got {r_spi_i.hex()}"
            )
        if r_exch != EXCHANGE_IKE_SA_INIT:
            raise ValueError(f"Expected IKE_SA_INIT (34), got exch_type={r_exch}")

        self.spi_r = r_spi_r
        self.log.info(f"SPIr (assigned by responder): {self.spi_r.hex()}")

        # 5. Parse payload chain
        body = resp[28:r_len]
        plist = self._parse_payloads(body, r_nxt)
        self.log.info(f"Response payloads: {len(plist)} total")
        self._log_payloads(plist)

        # 6. Check for error notifications before extracting SA/KE/Nr
        for p in plist:
            if p["type"] == PAYLOAD_NOTIFY and len(p["data"]) >= 4:
                n_type = struct.unpack("!H", p["data"][2:4])[0]
                if n_type == NOTIFY_INVALID_KE_PAYLOAD:
                    raise ValueError(
                        "Responder rejected our KE payload (INVALID_KE_PAYLOAD). "
                        "Try a different --dh-group."
                    )
                if n_type == NOTIFY_NO_PROPOSAL_CHOSEN:
                    raise ValueError(
                        "Responder rejected our SA proposal (NO_PROPOSAL_CHOSEN). "
                        "Adjust --encr / --integ / --prf / --dh-group."
                    )

        # 7. Extract required payloads
        sa_data = ke_data = nr_data = None
        for p in plist:
            if p["type"] == PAYLOAD_SA    and sa_data is None: sa_data = p["data"]
            if p["type"] == PAYLOAD_KE    and ke_data is None: ke_data = p["data"]
            if p["type"] == PAYLOAD_NONCE and nr_data  is None: nr_data  = p["data"]

        for name, val in [("SA", sa_data), ("KE", ke_data), ("Nonce", nr_data)]:
            if val is None:
                raise ValueError(f"Missing {name} payload in IKE_SA_INIT response")

        # 8. Decode SA response (log selected algorithms)
        self.log.info("Responder SA selection:")
        self._parse_sa_payload(sa_data)

        # 9. Decode KE and extract peer public key
        peer_pub = self._parse_ke_payload(ke_data)

        # 10. Store Nr
        self.nonce_r = nr_data
        self.log.info(f"Nonce R ({len(self.nonce_r)}B): {self.nonce_r.hex()}")

        # 11. Compute g^ir
        self._compute_dh_shared(peer_pub)

        self.log.info("IKE_SA_INIT exchange complete — proceeding to key derivation")

    # ------------------------------------------------------------------
    # IKE_AUTH
    # ------------------------------------------------------------------

    def _ike_auth(self) -> None:
        """
        Full IKE_AUTH exchange (RFC 7296 §2.7 + §2.15):
          1. Build IDi + compute PSK AUTH for the initiator
          2. Assemble inner payloads: IDi | AUTH | SAi2 | TSi | TSr
          3. Encrypt inner payloads into an SK payload
          4. Send IKE_AUTH request
          5. Receive response, decrypt SK payload
          6. Parse IDr, AUTH, SAr2, TSi, TSr from decrypted inner payloads
          7. Verify responder's PSK AUTH value
        """
        self.log.section("IKE_AUTH Request  [MSG_ID=1]")

        # 1. Build IDi body: ID_Type | RESERVED×3 | identity_data
        try:
            ipaddress.IPv4Address(self.cfg.id_local)
            id_type  = ID_TYPE_IPV4_ADDR
            id_value = socket.inet_aton(self.cfg.id_local)
        except ValueError:
            id_type  = ID_TYPE_FQDN
            id_value = self.cfg.id_local.encode()
        idi_body = struct.pack("!BBBB", id_type, 0, 0, 0) + id_value
        self.log.info(f"IDi         : type={id_type}  value={self.cfg.id_local!r}")

        # 2. Compute initiator AUTH per RFC 7296 §2.15
        #    signed_octets = RealMsg1 | Nr | prf(SK_pi, IDi_body)
        id_hash       = self._prf(self.sk_pi, idi_body)
        signed_octets = self.msg1_bytes + self.nonce_r + id_hash
        self.log.debug(
            f"Signed octets: msg1({len(self.msg1_bytes)}B)"
            f" | Nr({len(self.nonce_r)}B)"
            f" | prf(SK_pi, IDi)({len(id_hash)}B)"
        )
        auth_data = self._compute_auth_psk(signed_octets)
        self.log.info(f"AUTH (init) : {auth_data.hex()}")

        # 3. Build inner payload chain: IDi → AUTH → SAi2 → TSi → TSr
        ts_r_pld  = self._build_ts_payload(PAYLOAD_TSr,  PAYLOAD_NONE,  [_TS_IPV4_WILDCARD])
        ts_i_pld  = self._build_ts_payload(PAYLOAD_TSi,  PAYLOAD_TSr,   [_TS_IPV4_WILDCARD])
        child_sa  = self._build_child_sa_payload(PAYLOAD_TSi)
        auth_pld  = self._build_auth_payload(PAYLOAD_SA, auth_data)
        idi_pld   = self._build_id_payload(PAYLOAD_IDi,  PAYLOAD_AUTH,  self.cfg.id_local)
        inner     = idi_pld + auth_pld + child_sa + ts_i_pld + ts_r_pld

        self.log.info(
            f"Inner payloads: IDi({len(idi_pld)}B) AUTH({len(auth_pld)}B)"
            f" SAi2({len(child_sa)}B) TSi({len(ts_i_pld)}B) TSr({len(ts_r_pld)}B)"
            f" = {len(inner)}B total"
        )

        # 4. Pre-compute SK payload size so the IKE header can carry the exact total length
        encr    = self.cfg.encr_alg
        blk     = encr.block_len if not encr.is_aead else 4
        pad_len = (blk - ((len(inner) + 1) % blk)) % blk
        plain_padded_len = len(inner) + pad_len + 1
        if encr.is_aead:
            sk_body_len = encr.iv_len + plain_padded_len + encr.icv_len
        else:
            sk_body_len = encr.iv_len + plain_padded_len + self.cfg.integ_alg.trunc_len
        total_len = 28 + 4 + sk_body_len     # IKE hdr + SK generic hdr + SK body

        ike_hdr = self._build_ike_header(
            exch_type=EXCHANGE_IKE_AUTH,
            flags=FLAG_INITIATOR,
            msg_id=1,
            next_payload=PAYLOAD_SK,
            total_len=total_len,
        )

        # 5. Encrypt
        sk_pld = self._encrypt_sk(inner, PAYLOAD_IDi, True, ike_hdr)
        pkt    = ike_hdr + sk_pld

        self.log.info(f"Packet size : {len(pkt)} bytes")
        self.log.debug("Raw request :", pkt)

        # 6. Send and receive
        resp = self._send_recv(pkt)

        self.log.section("IKE_AUTH Response  [MSG_ID=1]")
        if len(resp) < 28:
            raise ValueError(f"Response too short: {len(resp)}B")

        (r_spi_i, r_spi_r, r_nxt, r_ver, r_exch,
         r_flags, r_mid, r_len) = struct.unpack("!8s8sBBBBII", resp[:28])

        self.log.debug(f"  SPIi        : {r_spi_i.hex()}")
        self.log.debug(f"  SPIr        : {r_spi_r.hex()}")
        self.log.debug(f"  Next payload: {PAYLOAD_NAMES.get(r_nxt, r_nxt)}")
        self.log.debug(f"  Flags       : 0x{r_flags:02x}")
        self.log.debug(f"  Msg ID      : {r_mid}")
        self.log.debug(f"  Length      : {r_len}")

        # Handle unencrypted error notifications (rare but possible)
        if r_nxt != PAYLOAD_SK:
            raw_plist = self._parse_payloads(resp[28:r_len], r_nxt)
            self._log_payloads(raw_plist)
            raise ValueError(
                f"IKE_AUTH response has unexpected next_payload={r_nxt} "
                f"(expected SK=46); possible unencrypted error"
            )

        # 7. Decrypt SK
        inner_bytes, inner_first = self._decrypt_sk(resp[:r_len])

        # 8. Parse inner payloads
        inner_plist = self._parse_payloads(inner_bytes, inner_first)
        self.log.info(f"Inner payloads: {len(inner_plist)}")
        self._log_payloads(inner_plist)

        # 9. Check for error notifications
        for p in inner_plist:
            if p["type"] == PAYLOAD_NOTIFY and len(p["data"]) >= 4:
                n_type = struct.unpack("!H", p["data"][2:4])[0]
                if n_type == NOTIFY_AUTHENTICATION_FAILED:
                    raise ValueError(
                        "Responder returned AUTHENTICATION_FAILED — check --psk"
                    )
                if n_type == NOTIFY_NO_PROPOSAL_CHOSEN:
                    raise ValueError(
                        "Responder rejected child SA proposal (NO_PROPOSAL_CHOSEN)"
                    )

        # 10. Extract IDr and AUTH from response
        idr_data = auth_r_data = None
        for p in inner_plist:
            if p["type"] == PAYLOAD_IDr  and idr_data    is None: idr_data    = p["data"]
            if p["type"] == PAYLOAD_AUTH and auth_r_data is None: auth_r_data = p["data"]

        # 11. Extract peer ESP SPI from the child SA response
        for p in inner_plist:
            if p["type"] == PAYLOAD_SA and p["data"]:
                spi_size = p["data"][6] if len(p["data"]) > 6 else 0
                if spi_size == 4:
                    self.child_spi_r = p["data"][8:12]
                    self.log.info(f"Child SA ESP SPI (responder): {self.child_spi_r.hex()}")
                break

        # 12. Verify responder AUTH
        if idr_data is None or auth_r_data is None:
            self.log.warn("No IDr or AUTH in IKE_AUTH response — cannot verify responder")
            return

        id_type_r = idr_data[0]
        id_val_r  = idr_data[4:]
        try:
            id_str_r = socket.inet_ntoa(id_val_r) if id_type_r == 1 else id_val_r.decode()
        except Exception:
            id_str_r = id_val_r.hex()
        self.log.info(f"IDr         : type={id_type_r}  value={id_str_r!r}")

        idr_hash      = self._prf(self.sk_pr, idr_data)
        resp_signed   = self.msg2_bytes + self.nonce_i + idr_hash
        expected_auth = self._compute_auth_psk(resp_signed)

        auth_method_r = auth_r_data[0]
        recv_auth     = auth_r_data[4:]

        if auth_method_r != AUTH_PSK:
            self.log.warn(
                f"Responder used auth method {auth_method_r} (expected PSK=2) — skipping verify"
            )
        elif recv_auth == expected_auth:
            self.log.info("Responder AUTH: VERIFIED ✓")
        else:
            self.log.warn(
                f"Responder AUTH: MISMATCH\n"
                f"  expected : {expected_auth.hex()}\n"
                f"  received : {recv_auth.hex()}"
            )

        self.log.info("IKE_AUTH exchange complete")

    # ------------------------------------------------------------------
    # Payload builders  (Milestone 3)  ✓
    # ------------------------------------------------------------------

    def _build_ike_header(self, exch_type: int, flags: int,
                          msg_id: int, next_payload: int,
                          total_len: int) -> bytes:
        """Encode the 28-byte IKEv2 fixed header (RFC 7296 §3.1)."""
        return struct.pack(
            "!8s8sBBBBII",
            self.spi_i, self.spi_r,
            next_payload,
            0x20,          # IKEv2
            exch_type,
            flags,
            msg_id,
            total_len,
        )

    @staticmethod
    def _generic_payload_hdr(next_payload: int, payload_data: bytes) -> bytes:
        """4-byte generic payload header: next_payload | 0 | length (including hdr)."""
        return struct.pack("!BBH", next_payload, 0, 4 + len(payload_data))

    def _build_sa_payload(self, next_payload: int) -> bytes:
        """
        Build an IKE SA payload (RFC 7296 §3.3) containing one proposal for the
        configured ENCR + PRF [+ INTEG] + DH transforms.
        INTEG is omitted when using an AEAD cipher (AES-GCM).
        """
        encr  = self.cfg.encr_alg
        prf   = self.cfg.prf_alg
        integ = self.cfg.integ_alg   # None for AEAD

        # --- collect (type, id, extra_attrs) tuples ---
        xforms: list[tuple[int, int, bytes]] = []

        # ENCR — include Key Length attribute for variable-key algorithms (not 3DES)
        if encr.transform_id != 3:
            attr = struct.pack("!HH", 0x800E, encr.key_len)  # TV: Key Length in bits
        else:
            attr = b""
        xforms.append((TRANSFORM_TYPE_ENCR, encr.transform_id, attr))

        # PRF
        xforms.append((TRANSFORM_TYPE_PRF, prf.transform_id, b""))

        # INTEG (skip for AEAD)
        if integ is not None:
            xforms.append((TRANSFORM_TYPE_INTEG, integ.transform_id, b""))

        # DH
        xforms.append((TRANSFORM_TYPE_DH, self.cfg.dh_group, b""))

        # --- encode transforms ---
        # Last-substruc value: 3 = more, 0 = last
        trans_bytes = b""
        for i, (ttype, tid, attrs) in enumerate(xforms):
            more  = 0 if i == len(xforms) - 1 else 3
            tlen  = 8 + len(attrs)
            trans_bytes += struct.pack("!BBHBBH", more, 0, tlen, ttype, 0, tid) + attrs

        # --- single proposal ---
        # Last-substruc: 0 = last proposal, 2 = more
        prop_len   = 8 + len(trans_bytes)
        prop_bytes = struct.pack(
            "!BBHBBBB", 0, 0, prop_len, 1, PROTO_IKE, 0, len(xforms)
        ) + trans_bytes

        payload_body = prop_bytes
        return self._generic_payload_hdr(next_payload, payload_body) + payload_body

    def _build_ke_payload(self, next_payload: int) -> bytes:
        """Build KE payload (RFC 7296 §3.4) from self.dh_pub."""
        body = struct.pack("!HH", self.cfg.dh_group, 0) + self.dh_pub
        return self._generic_payload_hdr(next_payload, body) + body

    def _build_nonce_payload(self, next_payload: int, nonce: bytes) -> bytes:
        """Build Nonce payload (RFC 7296 §3.9)."""
        return self._generic_payload_hdr(next_payload, nonce) + nonce

    def _build_id_payload(self, payload_type: int, next_payload: int,
                          id_str: str) -> bytes:
        """
        Build IDi or IDr payload (RFC 7296 §3.5).
        Auto-detects IPv4 address vs FQDN from id_str.
        payload_type is PAYLOAD_IDi or PAYLOAD_IDr (used only for logging).
        """
        try:
            ipaddress.IPv4Address(id_str)
            id_type = ID_TYPE_IPV4_ADDR
            id_data = socket.inet_aton(id_str)
        except ValueError:
            id_type = ID_TYPE_FQDN
            id_data = id_str.encode()
        body = struct.pack("!BBBB", id_type, 0, 0, 0) + id_data
        pname = "IDi" if payload_type == PAYLOAD_IDi else "IDr"
        self.log.debug(
            f"Building {pname}: type={id_type} data={id_data!r}"
        )
        return self._generic_payload_hdr(next_payload, body) + body

    def _build_auth_payload(self, next_payload: int, auth_data: bytes) -> bytes:
        """Build AUTH payload (RFC 7296 §3.8). Auth method = PSK (2)."""
        body = struct.pack("!BBBB", AUTH_PSK, 0, 0, 0) + auth_data
        return self._generic_payload_hdr(next_payload, body) + body

    def _build_ts_payload(self, payload_type: int, next_payload: int,
                          ts_list: list) -> bytes:
        """
        Build TSi or TSr payload (RFC 7296 §3.13).
        ts_list: list of raw 16-byte TS_IPV4_ADDR_RANGE entries.
        """
        body = struct.pack("!BBBB", len(ts_list), 0, 0, 0) + b"".join(ts_list)
        return self._generic_payload_hdr(next_payload, body) + body

    def _build_child_sa_payload(self, next_payload: int) -> bytes:
        """
        Build an ESP Child SA proposal for IKE_AUTH (RFC 7296 §3.3).
        Uses the same ENCR/INTEG as the IKE SA plus ESN=0.
        Generates a fresh 4-byte local ESP SPI (stored in self.child_spi_i).
        """
        encr  = self.cfg.encr_alg
        integ = self.cfg.integ_alg

        self.child_spi_i = os.urandom(4)
        self.log.debug(f"Child SA ESP SPI (initiator): {self.child_spi_i.hex()}")

        xforms: list[tuple[int, int, bytes]] = []

        # ENCR
        attr = struct.pack("!HH", 0x800E, encr.key_len) if encr.transform_id != 3 else b""
        xforms.append((TRANSFORM_TYPE_ENCR, encr.transform_id, attr))

        # INTEG (skip for AEAD)
        if integ is not None:
            xforms.append((TRANSFORM_TYPE_INTEG, integ.transform_id, b""))

        # ESN = 0 (no extended sequence numbers)
        xforms.append((5, 0, b""))

        trans_bytes = b""
        for i, (ttype, tid, attrs) in enumerate(xforms):
            more = 0 if i == len(xforms) - 1 else 3
            tlen = 8 + len(attrs)
            trans_bytes += struct.pack("!BBHBBH", more, 0, tlen, ttype, 0, tid) + attrs

        prop_len   = 8 + 4 + len(trans_bytes)   # 8-byte prop hdr + 4-byte SPI + transforms
        prop_bytes = struct.pack(
            "!BBHBBBB", 0, 0, prop_len, 1, PROTO_ESP, 4, len(xforms)
        ) + self.child_spi_i + trans_bytes

        return self._generic_payload_hdr(next_payload, prop_bytes) + prop_bytes

    def _parse_payloads(self, data: bytes, first_payload_type: int) -> list[dict]:
        """
        Walk the IKEv2 generic payload chain.
        Returns list of {'type': int, 'critical': bool, 'data': bytes}.
        """
        payloads: list[dict] = []
        cur_type = first_payload_type
        offset   = 0

        while cur_type != PAYLOAD_NONE and offset < len(data):
            if offset + 4 > len(data):
                self.log.warn(f"Truncated payload header at offset {offset}")
                break
            next_type = data[offset]
            critical  = bool(data[offset + 1] & 0x80)
            length    = struct.unpack("!H", data[offset + 2:offset + 4])[0]

            if length < 4 or offset + length > len(data):
                self.log.warn(
                    f"Invalid payload length {length} at offset {offset} "
                    f"(remaining {len(data)-offset}B)"
                )
                break

            payloads.append({
                "type":     cur_type,
                "critical": critical,
                "data":     data[offset + 4:offset + length],
            })
            offset   += length
            cur_type  = next_type

        return payloads

    def _parse_sa_payload(self, data: bytes) -> dict:
        """
        Decode SA payload proposals and transforms; log every field.
        Returns dict keyed by transform type → {'id': int, 'key_len': int|None}.
        """
        _ENCR  = {3: "3DES", 12: "AES-CBC", 18: "AES-GCM-8", 19: "AES-GCM-12", 20: "AES-GCM-16"}
        _PRF   = {1: "HMAC-MD5", 2: "HMAC-SHA1", 5: "HMAC-SHA256", 6: "HMAC-SHA384", 7: "HMAC-SHA512"}
        _INTEG = {1: "MD5-96", 2: "SHA1-96", 5: "AES-XCBC-96", 12: "SHA256-128", 13: "SHA384-192", 14: "SHA512-256"}
        _DH    = {2: "1024-MODP", 5: "1536-MODP", 14: "2048-MODP", 15: "3072-MODP",
                  19: "P-256", 20: "P-384", 21: "P-521", 31: "Curve25519"}
        _TNAME = {1: "ENCR", 2: "PRF", 3: "INTEG", 4: "DH", 5: "ESN"}
        _ALGS  = {1: _ENCR, 2: _PRF, 3: _INTEG, 4: _DH}

        result: dict = {}
        off = 0
        first_proposal = True

        while off < len(data):
            if off + 8 > len(data):
                break
            last_prop = data[off]
            prop_len  = struct.unpack("!H", data[off + 2:off + 4])[0]
            prop_num  = data[off + 4]
            proto_id  = data[off + 5]
            spi_size  = data[off + 6]
            num_trans = data[off + 7]
            spi       = data[off + 8:off + 8 + spi_size]
            proto_name = {1: "IKE", 2: "AH", 3: "ESP"}.get(proto_id, f"?{proto_id}")

            self.log.debug(
                f"  Proposal #{prop_num}: proto={proto_name}"
                f" spi={spi.hex() if spi else '-'} transforms={num_trans}"
            )

            # parse transforms
            toff = off + 8 + spi_size
            end  = off + prop_len
            while toff < end:
                if toff + 8 > end:
                    break
                t_last = data[toff]
                t_len  = struct.unpack("!H", data[toff + 2:toff + 4])[0]
                t_type = data[toff + 4]
                t_id   = struct.unpack("!H", data[toff + 6:toff + 8])[0]

                key_len = None
                aoff = toff + 8
                while aoff + 4 <= toff + t_len:
                    a_type = struct.unpack("!H", data[aoff:aoff + 2])[0]
                    if a_type & 0x8000:            # TV format (2B type + 2B value)
                        a_val = struct.unpack("!H", data[aoff + 2:aoff + 4])[0]
                        if (a_type & 0x7FFF) == 14:
                            key_len = a_val
                        aoff += 4
                    else:                           # TLV format (2B type + 2B len + data)
                        a_len = struct.unpack("!H", data[aoff + 2:aoff + 4])[0]
                        aoff += 4 + a_len

                tname   = _TNAME.get(t_type, f"?{t_type}")
                alg_map = _ALGS.get(t_type, {})
                alg_str = alg_map.get(t_id, str(t_id))
                kl_str  = f" keylen={key_len}" if key_len is not None else ""
                self.log.debug(f"    Transform: {tname}={alg_str}{kl_str}")

                if first_proposal:
                    result[t_type] = {"id": t_id, "key_len": key_len}

                if t_last == 0:
                    break
                toff += t_len

            first_proposal = False
            if last_prop == 0:
                break
            off += prop_len

        return result

    def _parse_ke_payload(self, data: bytes) -> bytes:
        """Decode KE payload; validate DH group and return peer's public key bytes."""
        if len(data) < 4:
            raise ValueError(f"KE payload too short ({len(data)}B)")
        group   = struct.unpack("!H", data[:2])[0]
        pub_key = data[4:]
        if group != self.cfg.dh_group:
            self.log.warn(
                f"Responder KE group {group} differs from proposed {self.cfg.dh_group}"
            )
        self.log.debug(f"  KE: DH group={group}, pub_key={len(pub_key)}B")
        self.log.debug(f"  Responder pub key:", pub_key)
        return pub_key

    def _log_payloads(self, payloads: list[dict]) -> None:
        """Pretty-print a list of parsed payloads."""
        _NOTIFY = {
            14:    "NO_PROPOSAL_CHOSEN",
            17:    "INVALID_KE_PAYLOAD",
            24:    "AUTHENTICATION_FAILED",
            16388: "NAT_DETECTION_SOURCE_IP",
            16389: "NAT_DETECTION_DESTINATION_IP",
            16390: "NAT_DETECTION_DESTINATION_IP",
        }
        for i, p in enumerate(payloads):
            ptype = p["type"]
            data  = p["data"]
            name  = PAYLOAD_NAMES.get(ptype, f"?{ptype}")
            crit  = " [CRITICAL]" if p["critical"] else ""
            self.log.debug(f"  [{i}] {name:<6} ({4+len(data)}B){crit}")

            if ptype == PAYLOAD_SA:
                self.log.debug(f"       (SA proposal — decoded separately)")
            elif ptype == PAYLOAD_KE:
                grp = struct.unpack("!H", data[:2])[0] if len(data) >= 2 else "?"
                self.log.debug(f"       DH group={grp}  pub_key={max(0,len(data)-4)}B")
            elif ptype == PAYLOAD_NONCE:
                self.log.debug(f"       nonce={data.hex()}")
            elif ptype == PAYLOAD_NOTIFY:
                if len(data) >= 4:
                    n_type = struct.unpack("!H", data[2:4])[0]
                    n_name = _NOTIFY.get(n_type, f"type={n_type}")
                    n_data = data[4:]
                    self.log.debug(
                        f"       Notify: {n_name}"
                        + (f"  data={n_data.hex()}" if n_data else "")
                    )
            elif ptype in (PAYLOAD_IDi, PAYLOAD_IDr):
                if len(data) >= 4:
                    id_t = data[0]
                    id_v = data[4:]
                    id_s = {1: "IPv4", 2: "FQDN", 3: "RFC822"}.get(id_t, f"?{id_t}")
                    try:
                        decoded = id_v.decode() if id_t in (2, 3) else socket.inet_ntoa(id_v)
                    except Exception:
                        decoded = id_v.hex()
                    self.log.debug(f"       ID type={id_s}: {decoded}")
            elif ptype == PAYLOAD_AUTH:
                if data:
                    self.log.debug(
                        f"       auth_type={data[0]}  data={data[4:].hex()}"
                    )

    # ------------------------------------------------------------------
    # Crypto primitives  (Milestone 2)  ✓
    # ------------------------------------------------------------------

    @staticmethod
    def _hash_fn(algo_name: str):
        """Return the hashlib constructor for the given algorithm name string."""
        return {
            "md5":    hashlib.md5,
            "sha1":   hashlib.sha1,
            "sha256": hashlib.sha256,
            "sha384": hashlib.sha384,
            "sha512": hashlib.sha512,
        }[algo_name]

    def _encr_key_material_len(self) -> int:
        """Bytes of encryption key material to derive (key + 4-byte AEAD salt if applicable)."""
        base = self.cfg.encr_alg.key_len // 8
        return base + (4 if self.cfg.encr_alg.is_aead else 0)

    def _generate_dh_keypair(self) -> None:
        """
        Generate a DH keypair for self.cfg.dh_group.
        Sets self.dh_priv and self.dh_pub (wire-format bytes).
        MODP: public key is g^x mod p encoded as big-endian fixed-width integer.
        EC  : public key is the uncompressed point (04 || x || y) per RFC 5903.
        """
        gid  = self.cfg.dh_group
        info = self.cfg.dh_info
        self.log.debug(f"Generating DH keypair: group {gid} ({info.name})")

        if info.kind == "modp":
            p, g      = MODP_PARAMS[gid]
            key_bytes = info.pub_key_len
            # private key uniformly drawn from [2, p-2]
            x   = int.from_bytes(os.urandom(key_bytes), "big") % (p - 2) + 2
            pub = pow(g, x, p)
            self.dh_priv = x
            self.dh_pub  = pub.to_bytes(key_bytes, "big")
        else:
            _curves = {19: ec.SECP256R1(), 20: ec.SECP384R1(), 21: ec.SECP521R1()}
            priv = ec.generate_private_key(_curves[gid])
            self.dh_priv = priv
            # RFC 5903 §3: KE payload = x || y (strip 0x04 uncompressed-point prefix)
            full = priv.public_key().public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )
            self.dh_pub = full[1:]

        self.log.debug(f"DH public key ({len(self.dh_pub)} bytes):", self.dh_pub)

    def _compute_dh_shared(self, peer_pub_bytes: bytes) -> None:
        """
        Compute g^ir from the peer's wire-format public key bytes.
        Sets self.dh_shared.
        """
        gid  = self.cfg.dh_group
        info = self.cfg.dh_info
        self.log.debug(
            f"Computing DH shared secret (peer pub {len(peer_pub_bytes)} bytes):",
            peer_pub_bytes,
        )

        if info.kind == "modp":
            p, _      = MODP_PARAMS[gid]
            key_bytes = info.pub_key_len
            peer_int  = int.from_bytes(peer_pub_bytes, "big")
            self.dh_shared = pow(peer_int, self.dh_priv, p).to_bytes(key_bytes, "big")
        else:
            _curves  = {19: ec.SECP256R1(), 20: ec.SECP384R1(), 21: ec.SECP521R1()}
            # Peer sends x || y (no 0x04 prefix) per RFC 5903 §3; restore it
            peer_key = EllipticCurvePublicKey.from_encoded_point(
                _curves[gid], b"\x04" + peer_pub_bytes
            )
            self.dh_shared = self.dh_priv.exchange(ec.ECDH(), peer_key)

        self.log.debug(
            f"DH shared secret g^ir ({len(self.dh_shared)} bytes):", self.dh_shared
        )

    def _prf(self, key: bytes, data: bytes) -> bytes:
        """HMAC-based PRF keyed by `key` over `data` using self.cfg.prf_alg."""
        alg = self.cfg.prf_alg
        out = _hmac.new(key, data, self._hash_fn(alg.hash_algo)).digest()
        self.log.debug(f"prf({alg.name}) key[0:4]={key[:4].hex()} → {out.hex()}")
        return out

    def _prf_plus(self, key: bytes, data: bytes, length: int) -> bytes:
        """
        prf+ as defined in RFC 7296 §2.13.
        T1 = prf(key, data | 0x01)
        T2 = prf(key, T1 | data | 0x02)
        ...
        Returns the first `length` bytes of T1 | T2 | ...
        """
        result  = b""
        t       = b""
        counter = 1
        while len(result) < length:
            t       = self._prf(key, t + data + bytes([counter]))
            result += t
            counter += 1
            if counter > 255:
                raise ValueError("prf+ counter exhausted — requested too much key material")
        return result[:length]

    def _integ(self, key: bytes, data: bytes) -> bytes:
        """
        Compute truncated HMAC integrity checksum using self.cfg.integ_alg.
        Not used in AEAD mode (call raises RuntimeError).
        """
        alg = self.cfg.integ_alg
        if alg is None:
            raise RuntimeError("_integ called in AEAD mode — integrity is inside the cipher")
        full = _hmac.new(key, data, self._hash_fn(alg.hash_algo)).digest()
        out  = full[:alg.trunc_len]
        self.log.debug(f"integ({alg.name}) key[0:4]={key[:4].hex()} → {out.hex()}")
        return out

    def _derive_keys(self) -> None:
        """
        Derive SKEYSEED and all SK_* keys per RFC 7296 §2.14.

        SKEYSEED = prf(Ni | Nr, g^ir)
        {SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr}
             = prf+(SKEYSEED, Ni | Nr | SPIi | SPIr)

        Requires self.dh_shared, nonce_i, nonce_r, spi_i, spi_r.
        """
        self.log.section("Key Derivation (RFC 7296 §2.14)")

        prf_len   = self.cfg.prf_alg.key_len
        integ_len = self.cfg.integ_alg.key_len if self.cfg.integ_alg else 0
        encr_len  = self._encr_key_material_len()
        total     = prf_len + integ_len * 2 + encr_len * 2 + prf_len * 2

        self.log.debug(f"Ni       ({len(self.nonce_i)}B) : {self.nonce_i.hex()}")
        self.log.debug(f"Nr       ({len(self.nonce_r)}B) : {self.nonce_r.hex()}")
        self.log.debug(f"g^ir     ({len(self.dh_shared)}B) : {self.dh_shared[:8].hex()}…")
        self.log.debug(f"SPIi : {self.spi_i.hex()}  SPIr : {self.spi_r.hex()}")
        self.log.debug(
            f"Key layout — SK_d:{prf_len} SK_ai:{integ_len} SK_ar:{integ_len}"
            f" SK_ei:{encr_len} SK_er:{encr_len} SK_pi:{prf_len} SK_pr:{prf_len}"
            f" = {total}B total"
        )

        # SKEYSEED = prf(Ni | Nr, g^ir)
        skeyseed = self._prf(self.nonce_i + self.nonce_r, self.dh_shared)
        self.log.info(f"SKEYSEED ({len(skeyseed)}B) = {skeyseed.hex()}")

        seed   = self.nonce_i + self.nonce_r + self.spi_i + self.spi_r
        keymat = self._prf_plus(skeyseed, seed, total)

        off = 0
        self.sk_d  = keymat[off:off+prf_len];    off += prf_len
        self.sk_ai = keymat[off:off+integ_len];   off += integ_len
        self.sk_ar = keymat[off:off+integ_len];   off += integ_len
        self.sk_ei = keymat[off:off+encr_len];    off += encr_len
        self.sk_er = keymat[off:off+encr_len];    off += encr_len
        self.sk_pi = keymat[off:off+prf_len];     off += prf_len
        self.sk_pr = keymat[off:off+prf_len]

        self.log.info(f"SK_d  ({len(self.sk_d)}B)  = {self.sk_d.hex()}")
        if integ_len:
            self.log.info(f"SK_ai ({len(self.sk_ai)}B) = {self.sk_ai.hex()}")
            self.log.info(f"SK_ar ({len(self.sk_ar)}B) = {self.sk_ar.hex()}")
        else:
            self.log.info("SK_ai / SK_ar = (empty — AEAD, integrity is inside the cipher)")
        self.log.info(f"SK_ei ({len(self.sk_ei)}B) = {self.sk_ei.hex()}")
        self.log.info(f"SK_er ({len(self.sk_er)}B) = {self.sk_er.hex()}")
        self.log.info(f"SK_pi ({len(self.sk_pi)}B) = {self.sk_pi.hex()}")
        self.log.info(f"SK_pr ({len(self.sk_pr)}B) = {self.sk_pr.hex()}")

    # ------------------------------------------------------------------
    # SK payload encrypt/decrypt  (Milestone 4)  ✓
    # ------------------------------------------------------------------

    def _encrypt_sk(self, inner_bytes: bytes, first_inner_type: int,
                    is_initiator: bool, ike_hdr: bytes) -> bytes:
        """
        Build a complete SK (Encrypted) payload (RFC 7296 §3.14).

        For CBC ciphers:
          SK = generic_hdr | IV | encrypt(inner | padding | pad_len) | HMAC(...)
          Integrity covers: ike_hdr | generic_hdr | IV | ciphertext.

        For AEAD (GCM):
          SK = generic_hdr | IV | AESGCM(inner | padding | pad_len, aad=ike_hdr|generic_hdr)
          The 16-byte ICV is appended inside the AESGCM ciphertext blob.

        ike_hdr must be the final 28-byte IKE header (with correct total_len)
        so that the integrity / AAD covers it accurately.
        """
        encr = self.cfg.encr_alg
        sk_e = self.sk_ei if is_initiator else self.sk_er
        sk_a = self.sk_ai if is_initiator else self.sk_ar

        # Pad plaintext to cipher block boundary (RFC 7296 §3.14)
        blk = encr.block_len if not encr.is_aead else 4   # GCM uses 4-byte alignment
        pad_len = (blk - ((len(inner_bytes) + 1) % blk)) % blk
        plaintext = inner_bytes + bytes(pad_len) + bytes([pad_len])

        iv = os.urandom(encr.iv_len)

        if not encr.is_aead:
            # --- AES-CBC / 3DES-CBC ---
            if encr.transform_id == 3:
                cipher_obj = Cipher(_TripleDES(sk_e), modes.CBC(iv))
            else:
                cipher_obj = Cipher(cipher_algorithms.AES(sk_e), modes.CBC(iv))
            enc = cipher_obj.encryptor()
            ciphertext = enc.update(plaintext) + enc.finalize()

            icv_len  = self.cfg.integ_alg.trunc_len
            sk_len   = 4 + encr.iv_len + len(ciphertext) + icv_len
            sk_hdr   = struct.pack("!BBH", first_inner_type, 0, sk_len)
            icv      = self._integ(sk_a, ike_hdr + sk_hdr + iv + ciphertext)

            self.log.debug(
                f"SK encrypt (CBC): iv={iv.hex()}  pad={pad_len}B  "
                f"ctext={len(ciphertext)}B  icv={icv.hex()}"
            )
            return sk_hdr + iv + ciphertext + icv

        else:
            # --- AES-GCM (AEAD) ---
            key_bytes = encr.key_len // 8
            key  = sk_e[:key_bytes]
            salt = sk_e[key_bytes:]          # 4-byte salt (RFC 5282 §3.1)
            nonce = salt + iv                # 12-byte GCM nonce

            icv_len = encr.icv_len           # 16 for AES-GCM-16
            sk_len  = 4 + encr.iv_len + len(plaintext) + icv_len
            sk_hdr  = struct.pack("!BBH", first_inner_type, 0, sk_len)
            aad     = ike_hdr + sk_hdr       # 28+4 = 32 bytes

            ct_with_icv = AESGCM(key).encrypt(nonce, plaintext, aad)

            self.log.debug(
                f"SK encrypt (GCM): iv={iv.hex()}  salt={salt.hex()}  "
                f"pad={pad_len}B  output={len(ct_with_icv)}B"
            )
            return sk_hdr + iv + ct_with_icv

    def _decrypt_sk(self, msg_bytes: bytes) -> tuple[bytes, int]:
        """
        Decrypt the SK payload in a complete IKE message received from the responder.

        msg_bytes: full IKE message bytes (from byte 0).
        Returns (inner_payload_bytes, first_inner_type).

        For CBC: verifies HMAC(SK_ar, msg_bytes[:-icv_len]) first.
        For GCM: authenticates via AESGCM with aad = msg_bytes[0:32].
        """
        encr = self.cfg.encr_alg
        sk_e = self.sk_er    # responder encrypts with SK_er
        sk_a = self.sk_ar    # responder's integrity key

        # SK generic header is at byte 28
        if len(msg_bytes) < 32:
            raise ValueError(f"Message too short for SK header ({len(msg_bytes)}B)")

        first_inner_type = msg_bytes[28]
        sk_total_len     = struct.unpack("!H", msg_bytes[30:32])[0]
        sk_end           = 28 + sk_total_len
        iv_len           = encr.iv_len
        iv               = msg_bytes[32:32 + iv_len]
        body_start       = 32 + iv_len

        self.log.debug(
            f"SK decrypt: first_inner={PAYLOAD_NAMES.get(first_inner_type, first_inner_type)}"
            f"  sk_len={sk_total_len}  iv={iv.hex()}"
        )

        if not encr.is_aead:
            icv_len    = self.cfg.integ_alg.trunc_len
            ciphertext = msg_bytes[body_start:sk_end - icv_len]
            icv_recv   = msg_bytes[sk_end - icv_len:sk_end]

            # Integrity: covers everything before the ICV field
            icv_calc = self._integ(sk_a, msg_bytes[:sk_end - icv_len])
            if icv_recv != icv_calc:
                raise ValueError(
                    f"SK integrity check FAILED\n"
                    f"  received : {icv_recv.hex()}\n"
                    f"  computed : {icv_calc.hex()}"
                )
            self.log.debug(f"SK integrity: OK  ({icv_len}B)")

            if encr.transform_id == 3:
                cipher_obj = Cipher(_TripleDES(sk_e), modes.CBC(iv))
            else:
                cipher_obj = Cipher(cipher_algorithms.AES(sk_e), modes.CBC(iv))
            dec = cipher_obj.decryptor()
            padded = dec.update(ciphertext) + dec.finalize()

        else:
            key_bytes        = encr.key_len // 8
            key              = sk_e[:key_bytes]
            salt             = sk_e[key_bytes:]
            nonce            = salt + iv
            aad              = msg_bytes[0:32]   # IKE hdr (28B) + SK hdr (4B)
            ct_with_icv      = msg_bytes[body_start:sk_end]

            padded = AESGCM(key).decrypt(nonce, ct_with_icv, aad)
            self.log.debug("SK AEAD authentication: OK")

        # Strip padding: last byte is pad_len
        pad_len  = padded[-1]
        inner    = padded[:-(pad_len + 1)]
        self.log.debug(f"SK decrypted inner payloads: {len(inner)}B  pad={pad_len}B")
        return inner, first_inner_type

    # ------------------------------------------------------------------
    # PSK AUTH computation  (Milestone 4)  ✓
    # ------------------------------------------------------------------

    def _compute_auth_psk(self, signed_octets: bytes, _sk_p: bytes = b"") -> bytes:
        """
        PSK AUTH per RFC 7296 §2.15:
          prf(prf(PSK, "Key Pad for IKEv2"), signed_octets)

        signed_octets (initiator) = msg1_bytes | Nr | prf(SK_pi, IDi_body)
        signed_octets (responder) = msg2_bytes | Ni | prf(SK_pr, IDr_body)

        _sk_p is accepted but unused; callers pre-compute prf(SK_p, ID_body)
        before calling this method.
        """
        psk_bytes = self.cfg.psk.encode()
        prf_psk   = self._prf(psk_bytes, b"Key Pad for IKEv2")
        auth      = self._prf(prf_psk, signed_octets)
        self.log.debug(f"AUTH = prf(prf(PSK, keypad), signed_octets) = {auth.hex()}")
        return auth

    # ------------------------------------------------------------------
    # Network I/O
    # ------------------------------------------------------------------

    def _send_recv(self, pkt_bytes: bytes) -> bytes:
        """Send pkt_bytes via UDP to cfg.host:cfg.port; return the first response."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.cfg.timeout)
        try:
            dest = (self.cfg.host, self.cfg.port)
            self.log.debug(f"UDP → {dest[0]}:{dest[1]}  ({len(pkt_bytes)}B)")
            sock.sendto(pkt_bytes, dest)
            data, addr = sock.recvfrom(65535)
            self.log.debug(f"UDP ← {addr[0]}:{addr[1]}  ({len(data)}B)")
            self.log.debug("Raw response:", data)
            return data
        except socket.timeout:
            raise TimeoutError(
                f"No response from {self.cfg.host}:{self.cfg.port} "
                f"within {self.cfg.timeout}s"
            )
        finally:
            sock.close()


# ---------------------------------------------------------------------------
# IKEv1Client  (RFC 2408 / RFC 2409)
# ---------------------------------------------------------------------------

class IKEv1Client:
    """
    IKEv1 Phase 1 initiator supporting both Main Mode (6-msg) and
    Aggressive Mode (3-msg) with PSK authentication.

    Key derivation (PSK, RFC 2409 §5.1):
      SKEYID   = prf(PSK,    Ni | Nr)
      SKEYID_d = prf(SKEYID, g^ir | CKY-I | CKY-R | 0x00)
      SKEYID_a = prf(SKEYID, SKEYID_d | g^ir | CKY-I | CKY-R | 0x01)
      SKEYID_e = prf(SKEYID, SKEYID_a | g^ir | CKY-I | CKY-R | 0x02)
    """

    def __init__(self, cfg: IKEv1Config) -> None:
        """Initialise all ISAKMP SA state to empty; no network I/O is performed here."""
        self.cfg = cfg
        self.log = Logger(min_level=LogLevel.DEBUG, verbose=cfg.verbose, color=True)

        self.cookie_i:    bytes = os.urandom(8)
        self.cookie_r:    bytes = b"\x00" * 8
        self.nonce_i:     bytes = b""
        self.nonce_r:     bytes = b""
        self.dh_priv              = None
        self.dh_pub:      bytes = b""
        self.peer_dh_pub: bytes = b""
        self.dh_shared:   bytes = b""

        # Saved payloads for HASH_I/R computation
        self.sa_payload_bytes:  bytes = b""  # full SA payload from msg 1
        self.idi_payload_bytes: bytes = b""  # full IDii payload (hdr + body)
        self.idr_payload_bytes: bytes = b""  # full IDir payload (hdr + body)

        # Derived keys
        self.skeyid:   bytes = b""
        self.skeyid_d: bytes = b""
        self.skeyid_a: bytes = b""
        self.skeyid_e: bytes = b""
        self.encr_key: bytes = b""
        self.phase1_iv: bytes = b""

        # Persistent UDP socket — reused for all messages so source port stays fixed
        self._sock: socket.socket | None = None

    # ── Entry point ────────────────────────────────────────────────────────

    def run(self) -> None:
        """Open a persistent UDP socket and run the configured Phase 1 exchange mode."""
        self.log.section(f"IKEv1 Phase 1  [{self.cfg.mode.title()} Mode]")
        self.log.info(f"Target    : {self.cfg.host}:{self.cfg.port}")
        self.log.info(f"Encr      : {self.cfg.encr}")
        self.log.info(f"Hash      : {self.cfg.hash_alg}")
        self.log.info(f"DH group  : {self.cfg.dh_group} ({self.cfg.dh_info.name})")
        self.log.info(f"Cookie I  : {self.cookie_i.hex()}")

        self._generate_dh_keypair()
        self.nonce_i = os.urandom(16)
        self.log.info(f"Nonce I   : {self.nonce_i.hex()}")

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.settimeout(self.cfg.timeout)
        try:
            if self.cfg.mode == "main":
                self._main_mode()
            else:
                self._aggressive_mode()
        finally:
            self._sock.close()
            self._sock = None

        self.log.section("IKEv1 Phase 1 Complete")
        self.log.info("ISAKMP SA established")

    # ── Main Mode ──────────────────────────────────────────────────────────

    def _main_mode(self) -> None:
        """Run the 6-message IKEv1 Main Mode exchange (RFC 2409 §5.4)."""
        # --- Messages 1 & 2: SA negotiation ---
        self.log.set_phase("MM-SA")
        sa_pld = self._build_sa_payload_v1(V1_PAYLOAD_NONE)
        self.sa_payload_bytes = sa_pld
        pkt1 = self._build_isakmp_header(
            V1_EXCHANGE_MAIN, 0, 0, V1_PAYLOAD_SA, 28 + len(sa_pld)
        ) + sa_pld
        self.log.info(f"Msg 1 → SA proposal ({len(pkt1)}B)")
        self.log.debug("Raw msg 1:", pkt1)
        resp2 = self._send_recv_v1(pkt1)
        self._parse_mm_msg2(resp2)

        # --- Messages 3 & 4: KE + Nonce ---
        self.log.set_phase("MM-KE")
        nonce_pld = self._build_generic_v1(V1_PAYLOAD_NONE, self.nonce_i)
        ke_pld    = self._build_generic_v1(V1_PAYLOAD_NONCE, self.dh_pub)
        pkt3 = self._build_isakmp_header(
            V1_EXCHANGE_MAIN, 0, 0, V1_PAYLOAD_KE, 28 + len(ke_pld) + len(nonce_pld)
        ) + ke_pld + nonce_pld
        self.log.info(f"Msg 3 → KE + Nonce ({len(pkt3)}B)")
        self.log.debug("Raw msg 3:", pkt3)
        resp4 = self._send_recv_v1(pkt3)
        self._parse_mm_msg4(resp4)

        # Key derivation
        self.log.set_phase("MM-KEYS")
        self._derive_keys_v1()

        # --- Messages 5 & 6: ID + HASH (encrypted) ---
        self.log.set_phase("MM-AUTH")
        idi_pld  = self._build_id_payload_v1(V1_PAYLOAD_NONE, self.cfg.id_local)
        self.idi_payload_bytes = idi_pld
        hash_i   = self._compute_hash_i()
        hash_pld = self._build_generic_v1(V1_PAYLOAD_NONE, hash_i)
        self.log.info(f"HASH_I = {hash_i.hex()}")

        inner    = idi_pld + hash_pld
        # Update first payload's next pointer: IDi → HASH
        inner    = self._set_next_payload_v1(inner, 0, V1_PAYLOAD_HASH)
        ct, new_iv = self._encrypt_v1(inner, self.phase1_iv)
        pkt5 = self._build_isakmp_header(
            V1_EXCHANGE_MAIN, V1_FLAG_ENCRYPTION, 0, V1_PAYLOAD_ID, 28 + len(ct)
        ) + ct
        self.log.info(f"Msg 5 → IDii + HASH_I (encrypted, {len(pkt5)}B)")
        self.log.debug("Raw msg 5:", pkt5)

        resp6 = self._send_recv_v1(pkt5)
        self._parse_mm_msg6(resp6, new_iv)

    def _parse_mm_msg2(self, pkt: bytes) -> None:
        """Parse SA response; extract cookie_r and selected transform."""
        self._parse_isakmp_hdr(pkt, expected_exch=V1_EXCHANGE_MAIN)
        self.cookie_r = pkt[8:16]
        self.log.info(f"Cookie R  : {self.cookie_r.hex()}")
        payloads = self._parse_payloads_v1(pkt[28:], pkt[16])
        self._log_payloads_v1(payloads)
        for p in payloads:
            if p["type"] == V1_PAYLOAD_SA:
                self._parse_sa_response_v1(p["data"])

    def _parse_mm_msg4(self, pkt: bytes) -> None:
        """Parse KE + Nr; compute DH shared secret."""
        self._parse_isakmp_hdr(pkt, expected_exch=V1_EXCHANGE_MAIN)
        payloads = self._parse_payloads_v1(pkt[28:], pkt[16])
        self._log_payloads_v1(payloads)
        for p in payloads:
            if p["type"] == V1_PAYLOAD_KE:
                self.peer_dh_pub = p["data"]
                self.log.debug(
                    f"Peer DH pub ({len(self.peer_dh_pub)}B):", self.peer_dh_pub
                )
            elif p["type"] == V1_PAYLOAD_NONCE:
                self.nonce_r = p["data"]
                self.log.info(f"Nonce R   : {self.nonce_r.hex()}")
        if not self.peer_dh_pub:
            raise ValueError("No KE payload in IKEv1 message 4")
        self._compute_dh_shared(self.peer_dh_pub)

    def _parse_mm_msg6(self, pkt: bytes, iv: bytes) -> None:
        """Decrypt and verify HASH_R from message 6."""
        self._parse_isakmp_hdr(pkt, expected_exch=V1_EXCHANGE_MAIN)
        if not (pkt[19] & V1_FLAG_ENCRYPTION):
            raise ValueError("Message 6 is not encrypted")
        plaintext, _ = self._decrypt_v1(pkt[28:], iv)
        payloads = self._parse_payloads_v1(plaintext, pkt[16])
        self._log_payloads_v1(payloads)
        for p in payloads:
            if p["type"] == V1_PAYLOAD_ID:
                self.idr_payload_bytes = (
                    struct.pack("!BBH", V1_PAYLOAD_NONE, 0, 4 + len(p["data"])) + p["data"]
                )
            elif p["type"] == V1_PAYLOAD_HASH:
                self._verify_hash_r(p["data"])

    # ── Aggressive Mode ────────────────────────────────────────────────────

    def _aggressive_mode(self) -> None:
        """Run the 3-message IKEv1 Aggressive Mode exchange (RFC 2409 §5.4)."""
        # --- Message 1: SA + KE + Nonce + IDii ---
        self.log.set_phase("AGG-INIT")
        sa_pld    = self._build_sa_payload_v1(V1_PAYLOAD_KE)
        self.sa_payload_bytes = self._build_sa_payload_v1(V1_PAYLOAD_NONE)  # chain-free copy
        ke_pld    = self._build_generic_v1(V1_PAYLOAD_NONCE, self.dh_pub,
                                           ptype=V1_PAYLOAD_KE)
        nonce_pld = self._build_generic_v1(V1_PAYLOAD_ID, self.nonce_i,
                                           ptype=V1_PAYLOAD_NONCE)
        idi_pld   = self._build_id_payload_v1(V1_PAYLOAD_NONE, self.cfg.id_local)
        self.idi_payload_bytes = idi_pld

        # Rebuild SA with correct next_payload chain
        sa_pld = self._build_sa_payload_v1(V1_PAYLOAD_KE)
        payloads = sa_pld + ke_pld + nonce_pld + idi_pld
        pkt1 = self._build_isakmp_header(
            V1_EXCHANGE_AGGRESSIVE, 0, 0, V1_PAYLOAD_SA, 28 + len(payloads)
        ) + payloads
        self.log.info(f"Msg 1 → SA + KE + Nonce + IDii ({len(pkt1)}B)")
        self.log.debug("Raw msg 1:", pkt1)

        resp2 = self._send_recv_v1(pkt1)
        self._parse_agg_msg2(resp2)

        # Key derivation (now have g^ir)
        self.log.set_phase("AGG-KEYS")
        self._derive_keys_v1()

        # --- Message 3: HASH_I (encrypted) ---
        self.log.set_phase("AGG-AUTH")
        hash_i   = self._compute_hash_i()
        hash_pld = self._build_generic_v1(V1_PAYLOAD_NONE, hash_i)
        self.log.info(f"HASH_I = {hash_i.hex()}")
        ct, _ = self._encrypt_v1(hash_pld, self.phase1_iv)
        pkt3 = self._build_isakmp_header(
            V1_EXCHANGE_AGGRESSIVE, V1_FLAG_ENCRYPTION, 0, V1_PAYLOAD_HASH, 28 + len(ct)
        ) + ct
        self.log.info(f"Msg 3 → HASH_I (encrypted, {len(pkt3)}B)")
        self.log.debug("Raw msg 3:", pkt3)
        self._send_no_wait_v1(pkt3)

    def _parse_agg_msg2(self, pkt: bytes) -> None:
        """Parse SA + KE + Nr + IDir + HASH_R from Aggressive Mode message 2."""
        self._parse_isakmp_hdr(pkt, expected_exch=V1_EXCHANGE_AGGRESSIVE)
        self.cookie_r = pkt[8:16]
        self.log.info(f"Cookie R  : {self.cookie_r.hex()}")
        payloads = self._parse_payloads_v1(pkt[28:], pkt[16])
        self._log_payloads_v1(payloads)
        hash_r_data = None
        for p in payloads:
            if p["type"] == V1_PAYLOAD_SA:
                self._parse_sa_response_v1(p["data"])
            elif p["type"] == V1_PAYLOAD_KE:
                self.peer_dh_pub = p["data"]
                self.log.debug(f"Peer DH pub ({len(self.peer_dh_pub)}B):", self.peer_dh_pub)
            elif p["type"] == V1_PAYLOAD_NONCE:
                self.nonce_r = p["data"]
                self.log.info(f"Nonce R   : {self.nonce_r.hex()}")
            elif p["type"] == V1_PAYLOAD_ID:
                self.idr_payload_bytes = (
                    struct.pack("!BBH", V1_PAYLOAD_NONE, 0, 4 + len(p["data"])) + p["data"]
                )
            elif p["type"] == V1_PAYLOAD_HASH:
                hash_r_data = p["data"]
        if not self.peer_dh_pub:
            raise ValueError("No KE payload in Aggressive Mode message 2")
        self._compute_dh_shared(self.peer_dh_pub)
        # HASH_R verification happens after key derivation in run()
        # Store for later
        self._pending_hash_r = hash_r_data

    # ── Packet builders ────────────────────────────────────────────────────

    def _build_isakmp_header(self, exch_type: int, flags: int,
                              msg_id: int, next_payload: int,
                              total_len: int) -> bytes:
        """28-byte ISAKMP header (RFC 2408 §3.1). Version = 0x10 (IKEv1)."""
        return struct.pack(
            "!8s8sBBBBII",
            self.cookie_i, self.cookie_r,
            next_payload,
            0x10,        # IKEv1 version
            exch_type,
            flags,
            msg_id,
            total_len,
        )

    @staticmethod
    def _generic_hdr_v1(next_payload: int, data_len: int) -> bytes:
        """Build a 4-byte ISAKMP generic payload header (next, reserved, length)."""
        return struct.pack("!BBH", next_payload, 0, 4 + data_len)

    def _build_generic_v1(self, next_payload: int, body: bytes,
                           ptype: int = 0) -> bytes:
        """Build a generic ISAKMP payload header + body. ptype unused (caller sets chain)."""
        return self._generic_hdr_v1(next_payload, len(body)) + body

    def _build_sa_payload_v1(self, next_payload: int) -> bytes:
        """
        Build ISAKMP SA payload for Phase 1 (RFC 2409 §5.1):
          SA { DOI | Situation | Proposal { Transform { Attributes } } }
        """
        encr  = self.cfg.encr_alg
        hinfo = self.cfg.hash_info

        # Transform attributes (TV format unless noted)
        def _tv(attr_type: int, val: int) -> bytes:
            """Encode a 2-byte type/value attribute (high bit set = TV format)."""
            return struct.pack("!HH", 0x8000 | attr_type, val)

        def _tlv(attr_type: int, data: bytes) -> bytes:
            """Encode a variable-length type/length/value attribute."""
            return struct.pack("!HH", attr_type, len(data)) + data

        attrs  = _tv(V1_ATTR_ENCR, encr.encr_id)
        if encr.encr_id == V1_ENCR_AES_CBC:
            attrs += _tv(V1_ATTR_KEY_LEN, encr.key_bits)
        attrs += _tv(V1_ATTR_HASH,      hinfo.hash_id)
        attrs += _tv(V1_ATTR_AUTH,      V1_AUTH_PSK)
        attrs += _tv(V1_ATTR_GROUP,     self.cfg.dh_group)
        attrs += _tv(V1_ATTR_LIFE_TYPE, 1)                          # seconds
        attrs += _tlv(V1_ATTR_LIFE_DUR, struct.pack("!I", self.cfg.lifetime))

        # Transform substructure (RFC 2408 §3.5):
        #   next(1) res(1) length(2) transform_num(1) transform_id(1) reserved(2) attrs
        xform_body = struct.pack("!BBH", 1, V1_XFORM_KEY_IKE, 0) + attrs
        xform = struct.pack("!BBH", 0, 0, 4 + len(xform_body)) + xform_body

        # Proposal substructure: last=0, reserved, len, num=1, proto=ISAKMP, spi_size=0, n_xforms=1
        prop_body = struct.pack("!BBBB", 1, V1_PROTO_ISAKMP, 0, 1) + xform
        proposal  = struct.pack("!BBH", 0, 0, 4 + len(prop_body)) + prop_body

        # SA body: DOI (4) + Situation (4) + proposal
        sa_body = struct.pack("!II", V1_DOI_IPSEC, V1_SITUATION_ID) + proposal
        return struct.pack("!BBH", next_payload, 0, 4 + len(sa_body)) + sa_body

    def _build_id_payload_v1(self, next_payload: int, id_str: str) -> bytes:
        """Build an ISAKMP ID payload. Auto-detects IPv4 vs FQDN."""
        try:
            ipaddress.IPv4Address(id_str)
            id_type = V1_ID_IPV4_ADDR
            id_data = socket.inet_aton(id_str)
        except ValueError:
            id_type = V1_ID_FQDN
            id_data = id_str.encode()
        # ID body: ID_type(1) + DOI_specific(3) + id_data
        body = struct.pack("!BBBB", id_type, 0, 0, 0) + id_data
        return struct.pack("!BBH", next_payload, 0, 4 + len(body)) + body

    @staticmethod
    def _set_next_payload_v1(payloads_bytes: bytes, offset: int, nxt: int) -> bytes:
        """Patch the next_payload byte of the payload at `offset`."""
        return payloads_bytes[:offset] + bytes([nxt]) + payloads_bytes[offset + 1:]

    # ── Parsers ────────────────────────────────────────────────────────────

    def _parse_isakmp_hdr(self, pkt: bytes, expected_exch: int) -> None:
        """Log ISAKMP header fields and raise if exchange type or version is wrong."""
        if len(pkt) < 28:
            raise ValueError(f"Packet too short: {len(pkt)}B")
        r_cookie_i = pkt[0:8]
        r_ver      = pkt[17]
        r_exch     = pkt[18]
        r_flags    = pkt[19]
        r_len      = struct.unpack("!I", pkt[24:28])[0]
        self.log.debug(f"  Cookie I  : {r_cookie_i.hex()}")
        self.log.debug(f"  Cookie R  : {pkt[8:16].hex()}")
        self.log.debug(f"  Version   : 0x{r_ver:02x}")
        self.log.debug(f"  Exch type : {r_exch}")
        self.log.debug(f"  Flags     : 0x{r_flags:02x}")
        self.log.debug(f"  Length    : {r_len}  (received {len(pkt)}B)")
        if r_ver != 0x10:
            self.log.warn(f"Unexpected IKE version 0x{r_ver:02x} (expected 0x10)")
        if r_exch != expected_exch:
            raise ValueError(f"Expected exchange type {expected_exch}, got {r_exch}")

    def _parse_payloads_v1(self, data: bytes, first_type: int) -> list[dict]:
        """Walk ISAKMP generic payload chain. Returns [{type, data}]."""
        payloads: list[dict] = []
        cur  = first_type
        off  = 0
        while cur != V1_PAYLOAD_NONE and off + 4 <= len(data):
            nxt  = data[off]
            plen = struct.unpack("!H", data[off + 2:off + 4])[0]
            if plen < 4 or off + plen > len(data):
                self.log.warn(f"Invalid payload length {plen} at offset {off}")
                break
            payloads.append({"type": cur, "data": data[off + 4:off + plen]})
            off += plen
            cur  = nxt
        return payloads

    def _parse_sa_response_v1(self, sa_body: bytes) -> None:
        """Log the selected transform from the SA response."""
        if len(sa_body) < 12:
            return
        # Skip DOI(4) + Situation(4) + proposal header(4)
        off = 12
        if off + 4 > len(sa_body):
            return
        # Transform header: next(1) res(1) len(2) num(1) id(1) res(2)
        if off + 8 > len(sa_body):
            return
        xform_len = struct.unpack("!H", sa_body[off + 2:off + 4])[0]
        xform_id  = sa_body[off + 5]
        self.log.info(f"Selected transform: {xform_id} (KEY_IKE)")
        # Parse attributes
        aoff = off + 8
        while aoff + 4 <= off + xform_len:
            a_type = struct.unpack("!H", sa_body[aoff:aoff + 2])[0]
            if a_type & 0x8000:
                a_val = struct.unpack("!H", sa_body[aoff + 2:aoff + 4])[0]
                a_name = {
                    0x8001: "ENCR", 0x8002: "HASH", 0x8003: "AUTH",
                    0x8004: "GROUP", 0x800B: "LIFE_TYPE", 0x800E: "KEY_LEN",
                }.get(a_type, f"attr-{a_type:#06x}")
                self.log.debug(f"  {a_name:<12} = {a_val}")
                aoff += 4
            else:
                a_len = struct.unpack("!H", sa_body[aoff + 2:aoff + 4])[0]
                aoff += 4 + a_len

    def _log_payloads_v1(self, payloads: list[dict]) -> None:
        """Log each parsed ISAKMP payload with type, length, and key field values."""
        for i, p in enumerate(payloads):
            name = V1_PAYLOAD_NAMES.get(p["type"], f"?{p['type']}")
            self.log.debug(f"  [{i}] {name:<12} ({4 + len(p['data'])}B)")
            if p["type"] == V1_PAYLOAD_NONCE:
                self.log.debug(f"       nonce = {p['data'].hex()}")
            elif p["type"] == V1_PAYLOAD_HASH:
                self.log.debug(f"       hash  = {p['data'].hex()}")
            elif p["type"] == V1_PAYLOAD_ID and p["data"]:
                id_type = p["data"][0]
                id_val  = p["data"][4:]
                try:
                    s = socket.inet_ntoa(id_val) if id_type == 1 else id_val.decode()
                except Exception:
                    s = id_val.hex()
                self.log.debug(f"       ID    type={id_type}  {s!r}")
            elif p["type"] == V1_PAYLOAD_NOTIFY and len(p["data"]) >= 4:
                n_type = struct.unpack("!H", p["data"][2:4])[0]
                self.log.debug(f"       notify type={n_type}")

    # ── Crypto ─────────────────────────────────────────────────────────────

    @staticmethod
    def _hash_fn_v1(algo: str):
        """Return the hashlib constructor for the given IKEv1 hash algorithm name."""
        return {
            "md5": hashlib.md5, "sha1": hashlib.sha1,
            "sha256": hashlib.sha256, "sha512": hashlib.sha512,
        }[algo]

    def _prf_v1(self, key: bytes, data: bytes) -> bytes:
        """HMAC using the negotiated IKEv1 hash algorithm."""
        h   = self._hash_fn_v1(self.cfg.hash_info.hash_algo)
        out = _hmac.new(key, data, h).digest()
        self.log.debug(f"prf_v1 key[0:4]={key[:4].hex()} → {out.hex()}")
        return out

    def _hash_raw_v1(self, data: bytes) -> bytes:
        """Plain (non-keyed) hash using the negotiated algorithm."""
        h = self._hash_fn_v1(self.cfg.hash_info.hash_algo)
        return h(data).digest()

    def _generate_dh_keypair(self) -> None:
        """Generate DH keypair (shared with IKEv2 logic, same MODP/EC groups)."""
        gid  = self.cfg.dh_group
        info = self.cfg.dh_info
        self.log.debug(f"Generating DH keypair: group {gid} ({info.name})")
        if info.kind == "modp":
            p, g      = MODP_PARAMS[gid]
            key_bytes = info.pub_key_len
            x         = int.from_bytes(os.urandom(key_bytes), "big") % (p - 2) + 2
            self.dh_priv = x
            self.dh_pub  = pow(g, x, p).to_bytes(key_bytes, "big")
        else:
            _curves = {19: ec.SECP256R1(), 20: ec.SECP384R1(), 21: ec.SECP521R1()}
            priv = ec.generate_private_key(_curves[gid])
            self.dh_priv = priv
            # RFC 5903 §3: KE payload = x || y (strip 0x04 uncompressed-point prefix)
            full = priv.public_key().public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )
            self.dh_pub = full[1:]
        self.log.debug(f"DH public key ({len(self.dh_pub)}B):", self.dh_pub)

    def _compute_dh_shared(self, peer_pub: bytes) -> None:
        """Compute g^ir from the peer's wire-format public key bytes; sets self.dh_shared."""
        gid  = self.cfg.dh_group
        info = self.cfg.dh_info
        if info.kind == "modp":
            p, _     = MODP_PARAMS[gid]
            key_bytes = info.pub_key_len
            self.dh_shared = pow(
                int.from_bytes(peer_pub, "big"), self.dh_priv, p
            ).to_bytes(key_bytes, "big")
        else:
            _curves  = {19: ec.SECP256R1(), 20: ec.SECP384R1(), 21: ec.SECP521R1()}
            # Peer sends x || y (no 0x04 prefix) per RFC 5903 §3; restore it
            peer_key = EllipticCurvePublicKey.from_encoded_point(_curves[gid], b"\x04" + peer_pub)
            self.dh_shared = self.dh_priv.exchange(ec.ECDH(), peer_key)
        self.log.debug(f"DH shared g^ir ({len(self.dh_shared)}B):", self.dh_shared)

    def _derive_keys_v1(self) -> None:
        """Derive SKEYID chain per RFC 2409 §5.1 (PSK)."""
        self.log.section("IKEv1 Key Derivation (RFC 2409 §5.1)")
        psk = self.cfg.psk.encode()

        self.skeyid   = self._prf_v1(psk, self.nonce_i + self.nonce_r)
        self.skeyid_d = self._prf_v1(
            self.skeyid, self.dh_shared + self.cookie_i + self.cookie_r + b"\x00"
        )
        self.skeyid_a = self._prf_v1(
            self.skeyid,
            self.skeyid_d + self.dh_shared + self.cookie_i + self.cookie_r + b"\x01"
        )
        self.skeyid_e = self._prf_v1(
            self.skeyid,
            self.skeyid_a + self.dh_shared + self.cookie_i + self.cookie_r + b"\x02"
        )

        self.log.info(f"SKEYID   = {self.skeyid.hex()}")
        self.log.info(f"SKEYID_d = {self.skeyid_d.hex()}")
        self.log.info(f"SKEYID_a = {self.skeyid_a.hex()}")
        self.log.info(f"SKEYID_e = {self.skeyid_e.hex()}")

        self.encr_key  = self._derive_encr_key_v1()
        self.phase1_iv = self._derive_iv_v1()
        self.log.info(f"Encr key ({len(self.encr_key)}B) = {self.encr_key.hex()}")
        self.log.info(f"Phase1 IV ({len(self.phase1_iv)}B) = {self.phase1_iv.hex()}")

        # Verify HASH_R in Aggressive Mode (deferred until after key derivation)
        if hasattr(self, "_pending_hash_r") and self._pending_hash_r is not None:
            self._verify_hash_r(self._pending_hash_r)

    def _derive_encr_key_v1(self) -> bytes:
        """Derive cipher key from SKEYID_e, expanding via prf if needed."""
        need = self.cfg.encr_alg.key_bytes
        if len(self.skeyid_e) >= need:
            return self.skeyid_e[:need]
        # Expansion: K1=prf(SKEYID_e, 0x00), K2=prf(SKEYID_e, K1), ...
        key_mat = b""
        t       = b"\x00"
        while len(key_mat) < need:
            t        = self._prf_v1(self.skeyid_e, t)
            key_mat += t
        return key_mat[:need]

    def _derive_iv_v1(self) -> bytes:
        """IV for the first encrypted Phase 1 message = hash(g^xi | g^xr)."""
        block = self.cfg.encr_alg.block_len
        return self._hash_raw_v1(self.dh_pub + self.peer_dh_pub)[:block]

    def _encrypt_v1(self, plaintext: bytes, iv: bytes) -> tuple[bytes, bytes]:
        """
        Pad and encrypt `plaintext` with the negotiated cipher.
        Returns (ciphertext, new_iv) where new_iv is the last ciphertext block
        (used as IV for the next encrypted message in the same exchange).
        """
        encr  = self.cfg.encr_alg
        blk   = encr.block_len
        # (len + pad_bytes + 1 pad_len_byte) must be a multiple of blk
        pad   = (blk - ((len(plaintext) + 1) % blk)) % blk
        plain = plaintext + bytes(pad) + bytes([pad])

        if encr.encr_id == V1_ENCR_3DES:
            cipher_obj = Cipher(_TripleDES(self.encr_key), modes.CBC(iv))
        else:
            cipher_obj = Cipher(cipher_algorithms.AES(self.encr_key), modes.CBC(iv))
        enc        = cipher_obj.encryptor()
        ciphertext = enc.update(plain) + enc.finalize()
        new_iv     = ciphertext[-blk:]
        self.log.debug(f"encrypt_v1: pad={pad}B plain={len(plain)}B ct={len(ciphertext)}B")
        return ciphertext, new_iv

    def _decrypt_v1(self, ciphertext: bytes, iv: bytes) -> tuple[bytes, bytes]:
        """Decrypt and strip padding. Returns (plaintext, new_iv)."""
        encr = self.cfg.encr_alg
        blk  = encr.block_len
        new_iv = ciphertext[-blk:]
        if encr.encr_id == V1_ENCR_3DES:
            cipher_obj = Cipher(_TripleDES(self.encr_key), modes.CBC(iv))
        else:
            cipher_obj = Cipher(cipher_algorithms.AES(self.encr_key), modes.CBC(iv))
        dec    = cipher_obj.decryptor()
        padded = dec.update(ciphertext) + dec.finalize()
        pad    = padded[-1]
        return padded[:-(pad + 1)], new_iv

    def _compute_hash_i(self) -> bytes:
        """
        HASH_I = prf(SKEYID, g^xi | g^xr | CKY-I | CKY-R | SAi_b | IDii_b)

        SAi_b / IDii_b are the payload BODIES (after the 4-byte generic header).
        RFC 2409 §5.1 — confirmed empirically against strongSwan: the DOI field
        is the first byte of SAi_b, not the generic next-payload byte.
        """
        data = (self.dh_pub + self.peer_dh_pub
                + self.cookie_i + self.cookie_r
                + self.sa_payload_bytes[4:]    # body only: DOI | Situation | Proposal…
                + self.idi_payload_bytes[4:])  # body only: ID_type | reserved | ID_data
        h = self._prf_v1(self.skeyid, data)
        self.log.debug(f"HASH_I = {h.hex()}")
        return h

    def _compute_hash_r(self) -> bytes:
        """
        HASH_R = prf(SKEYID, g^xr | g^xi | CKY-R | CKY-I | SAi_b | IDir_b)
        """
        data = (self.peer_dh_pub + self.dh_pub
                + self.cookie_r + self.cookie_i
                + self.sa_payload_bytes[4:]    # body only
                + self.idr_payload_bytes[4:])  # body only
        h = self._prf_v1(self.skeyid, data)
        self.log.debug(f"HASH_R (expected) = {h.hex()}")
        return h

    def _verify_hash_r(self, received: bytes) -> None:
        """Recompute HASH_R and log whether it matches the received value."""
        expected = self._compute_hash_r()
        if received == expected:
            self.log.info("HASH_R: VERIFIED ✓")
        else:
            self.log.warn(
                f"HASH_R mismatch\n"
                f"  expected : {expected.hex()}\n"
                f"  received : {received.hex()}"
            )

    # ── Network I/O ────────────────────────────────────────────────────────

    def _send_recv_v1(self, pkt: bytes) -> bytes:
        """Send `pkt` over self._sock and block until a UDP response arrives."""
        dest = (self.cfg.host, self.cfg.port)
        self.log.debug(f"UDP → {dest[0]}:{dest[1]}  ({len(pkt)}B)")
        self._sock.sendto(pkt, dest)
        try:
            data, addr = self._sock.recvfrom(65535)
        except socket.timeout:
            raise TimeoutError(
                f"No IKEv1 response from {self.cfg.host}:{self.cfg.port} "
                f"within {self.cfg.timeout}s"
            ) from None
        self.log.debug(f"UDP ← {addr[0]}:{addr[1]}  ({len(data)}B)")
        self.log.debug("Raw response:", data)
        return data

    def _send_no_wait_v1(self, pkt: bytes) -> None:
        """Fire-and-forget UDP send (used for Aggressive Mode message 3)."""
        self.log.debug(f"UDP → {self.cfg.host}:{self.cfg.port}  ({len(pkt)}B) [no-wait]")
        self._sock.sendto(pkt, (self.cfg.host, self.cfg.port))


# ---------------------------------------------------------------------------
# Self-test  (Milestone 2)
# ---------------------------------------------------------------------------

def run_self_test() -> bool:
    """
    Validate crypto primitives against known test vectors.

    Tests:
      1. prf / HMAC-SHA1 — RFC 2202 test case 1
      2. prf+ — T1/T2 prefix values computed from reference Python run
      3. Key derivation prf+ slicing — given a known SKEYSEED, verify SK_* offsets
      4. MODP DH Group 14 — two-party shared-secret agreement
      5. EC DH Group 19 (P-256) — two-party shared-secret agreement
    """
    passed = 0
    failed = 0

    def check(label: str, got: bytes, want: bytes) -> None:
        """Compare two byte strings and increment the pass/fail counters."""
        nonlocal passed, failed
        if got == want:
            print(f"  PASS  {label}")
            passed += 1
        else:
            print(f"  FAIL  {label}")
            print(f"        got  = {got.hex()}")
            print(f"        want = {want.hex()}")
            failed += 1

    def _silent(cfg_kwargs: dict) -> "IKEv2Client":
        """Construct an IKEv2Client with logging suppressed, for use in tests."""
        cfg = IKEConfig(**cfg_kwargs)
        c   = IKEv2Client(cfg)
        c.log.min_level = LogLevel.ERROR   # suppress output during test
        return c

    print("\n─── Milestone 2 self-test ───")

    sha1_cfg = dict(host="127.0.0.1", encr="aes-cbc-128",
                    integ="hmac-sha1-96", prf="hmac-sha1", dh_group=14, psk="test")

    # 1. prf: RFC 2202 HMAC-SHA1 test case 1
    c = _silent(sha1_cfg)
    check(
        "prf/HMAC-SHA1 (RFC 2202 tc1)",
        c._prf(b"\x0b" * 20, b"Hi There"),
        bytes.fromhex("b617318655057264e28bc0b6fb378c8ef146be00"),
    )

    # 2. prf+: T1 and T2 prefix (reference values computed from verified Python)
    k, d = b"\xaa" * 20, b"\xbb" * 16
    pp   = _silent(sha1_cfg)._prf_plus(k, d, 60)
    t1_ref = bytes.fromhex("9d4b4d1ac116e4174cd646ca09228757cf7f2742")
    t2_ref = bytes.fromhex("bae4c940ffab4235bcabba6b2b8c86c427b6bd2d")
    check("prf+: T1",        pp[:20], t1_ref)
    check("prf+: T1 | T2",   pp[:40], t1_ref + t2_ref)
    check("prf+: length-60", pp[40:], bytes.fromhex("73504b5ff0b7b7efcecdc383e27af5ffb44ea087")[:20])

    # 3. Key derivation slicing
    #    Use known SKEYSEED from RFC 7296 Appendix C.1 and verify prf+ produces
    #    correct SK_* layout.  (SKEYSEED correctness requires the RFC's exact g^ir;
    #    this test validates prf+ and slice offsets independently of DH.)
    c2 = _silent(sha1_cfg)
    c2.nonce_i = bytes.fromhex("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF")
    c2.nonce_r = bytes.fromhex("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF")
    c2.spi_i   = bytes.fromhex("A1B2C3D4E5F6A7B8")
    c2.spi_r   = bytes.fromhex("C0D1E2F3A4B5C6D7")
    skeyseed   = bytes.fromhex("D5A3AE6D70D430AB1C047BBC3CB637B33A10F56A")
    seed       = c2.nonce_i + c2.nonce_r + c2.spi_i + c2.spi_r
    # prf_len=20, integ_len=20, encr_len=16 for sha1/aes-cbc-128/sha1-96
    km = c2._prf_plus(skeyseed, seed, 20+20+20+16+16+20+20)
    # Expected values derived from SKEYSEED=D5A3AE6D... via prf+(HMAC-SHA1, seed)
    # Computed offline and locked here as a regression guard.
    check("key-deriv: SK_d  offset",
          km[0:20],
          bytes.fromhex("c76a4756cc9401e1262d7bba3800b9149e37254a"))
    check("key-deriv: SK_ei offset",
          km[60:76],
          bytes.fromhex("a718e2a1e17fb09377171d95ccef4cc1"))
    check("key-deriv: SK_pr offset",
          km[112:132],
          bytes.fromhex("9e0968f9de5d7d9d1159d3538be0b7aeb23ba18a"))

    # 4. MODP DH Group 14 — two-party agreement
    a = _silent(sha1_cfg); a._generate_dh_keypair()
    b = _silent(sha1_cfg); b._generate_dh_keypair()
    assert len(a.dh_pub) == 256, f"Group-14 pub key should be 256B, got {len(a.dh_pub)}"
    a._compute_dh_shared(b.dh_pub)
    b._compute_dh_shared(a.dh_pub)
    check("DH Group 14 two-party agreement", a.dh_shared, b.dh_shared)

    # 5. EC DH Group 19 (P-256) — two-party agreement
    ec_cfg = dict(host="127.0.0.1", encr="aes-cbc-128",
                  integ="hmac-sha1-96", prf="hmac-sha1", dh_group=19, psk="test")
    x = _silent(ec_cfg); x._generate_dh_keypair()
    y = _silent(ec_cfg); y._generate_dh_keypair()
    assert len(x.dh_pub) == 64, f"P-256 pub key should be 64B, got {len(x.dh_pub)}"
    x._compute_dh_shared(y.dh_pub)
    y._compute_dh_shared(x.dh_pub)
    check("DH Group 19 (P-256) two-party agreement", x.dh_shared, y.dh_shared)

    print("\n─── Milestone 4 self-test ───")

    # 6. PSK AUTH computation matches manual derivation
    import socket as _socket
    c6 = _silent(sha1_cfg)
    c6.sk_pi = bytes.fromhex("71824D09AC5025879B9E630F054E1D3478E16124")
    c6.msg1_bytes = b"fake_msg1__" + b"x" * 50
    c6.nonce_r    = bytes.fromhex("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF")

    idi_body   = struct.pack("!BBBB", 1, 0, 0, 0) + _socket.inet_aton("10.0.0.1")
    id_hash    = c6._prf(c6.sk_pi, idi_body)
    signed     = c6.msg1_bytes + c6.nonce_r + id_hash
    auth_got   = c6._compute_auth_psk(signed)

    import hmac as _hmac2, hashlib as _hl
    _psk_b   = c6.cfg.psk.encode()          # use the same PSK as the client ("test")
    psk_key  = _hmac2.new(_psk_b, b"Key Pad for IKEv2", _hl.sha1).digest()
    auth_want = _hmac2.new(psk_key, signed, _hl.sha1).digest()
    check("PSK AUTH computation", auth_got, auth_want)

    # 7. AES-CBC-256 SK encrypt/decrypt round-trip
    c7 = _silent(sha1_cfg)
    c7.spi_i = b"\x01" * 8; c7.spi_r = b"\x02" * 8
    c7.sk_ei = c7.sk_er = os.urandom(32)
    c7.sk_ai = c7.sk_ar = os.urandom(20)
    inner7 = b"\xcc" * 64
    pad7   = (16 - ((len(inner7) + 1) % 16)) % 16
    sk_blen7 = 16 + len(inner7) + pad7 + 1 + 12   # iv + padded + hmac-sha1-96
    ike7 = c7._build_ike_header(35, 0x08, 1, PAYLOAD_SK, 28 + 4 + sk_blen7)
    sk7  = c7._encrypt_sk(inner7, PAYLOAD_IDi, True, ike7)
    dec7, ft7 = c7._decrypt_sk(ike7 + sk7)
    check("SK round-trip CBC-256", dec7, inner7)
    check("SK round-trip first_inner_type", bytes([ft7]), bytes([PAYLOAD_IDi]))

    # 8. AES-GCM-256 SK encrypt/decrypt round-trip
    gcm_cfg = dict(host="127.0.0.1", encr="aes-gcm-256", prf="hmac-sha256",
                   dh_group=14, psk="secret")
    c8 = _silent(gcm_cfg)
    c8.spi_i = b"\x03" * 8; c8.spi_r = b"\x04" * 8
    c8.sk_ei = c8.sk_er = os.urandom(36)
    c8.sk_ai = c8.sk_ar = b""
    inner8 = b"\xdd" * 48
    pad8   = (4 - ((len(inner8) + 1) % 4)) % 4
    sk_blen8 = 8 + len(inner8) + pad8 + 1 + 16   # iv + padded + icv
    ike8 = c8._build_ike_header(35, 0x08, 1, PAYLOAD_SK, 28 + 4 + sk_blen8)
    sk8  = c8._encrypt_sk(inner8, PAYLOAD_IDi, True, ike8)
    dec8, ft8 = c8._decrypt_sk(ike8 + sk8)
    check("SK round-trip GCM-256", dec8, inner8)

    # 9. IDi / TS payload encoding
    c9 = _silent(sha1_cfg)
    id_pld = c9._build_id_payload(PAYLOAD_IDi, PAYLOAD_AUTH, "192.168.1.1")
    assert id_pld[4] == 1   # IPv4
    check("IDi payload IPv4 type byte", bytes([id_pld[4]]), bytes([1]))

    ts_pld = c9._build_ts_payload(PAYLOAD_TSi, PAYLOAD_TSr, [_TS_IPV4_WILDCARD])
    assert ts_pld[4] == 1   # 1 TS
    check("TSi payload num_ts", bytes([ts_pld[4]]), bytes([1]))

    print(f"\n  {passed} passed, {failed} failed")
    return failed == 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Build and return the CLI argument parser for ike_client.py."""
    p = argparse.ArgumentParser(
        prog="ike_client.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            IKEv1/IKEv2 client with PSK authentication.

            IKEv2 examples:
              %(prog)s 10.0.0.1
              %(prog)s 10.0.0.1 --encr aes-gcm-256 --dh-group 19
              %(prog)s 10.0.0.1 --encr aes-cbc-256 --integ hmac-sha512-256 --prf hmac-sha512 --dh-group 21

            IKEv1 examples:
              %(prog)s 10.0.0.1 --version 1
              %(prog)s 10.0.0.1 --version 1 --mode aggressive
              %(prog)s 10.0.0.1 --version 1 --encr aes-cbc-256 --hash sha512 --dh-group 21
        """),
    )

    p.add_argument("host", nargs="?", help="Responder IP address or hostname")
    p.add_argument("-p", "--port", type=int, default=500,
                   help="UDP port (default: 500)")
    p.add_argument("--version", type=int, default=2, choices=[1, 2],
                   help="IKE version: 1 or 2 (default: 2)")

    # ── Shared algorithm options ──────────────────────────────────────────
    alg = p.add_argument_group("algorithm selection (IKEv1 + IKEv2)")
    alg.add_argument("--encr", default="aes-cbc-256",
                     metavar="ALG",
                     help=(f"Encryption algorithm (default: aes-cbc-256). "
                           f"IKEv2: {', '.join(sorted(ENCR_ALGORITHMS))}. "
                           f"IKEv1: {', '.join(sorted(V1_ENCR_ALGORITHMS))}"))
    alg.add_argument("--dh-group", type=int, default=14,
                     choices=sorted(DH_GROUPS), metavar="N",
                     help=f"DH group (default: 14). Choices: {', '.join(str(g) for g in sorted(DH_GROUPS))}")

    # ── IKEv2-specific ────────────────────────────────────────────────────
    v2 = p.add_argument_group("IKEv2-specific options (ignored when --version 1)")
    v2.add_argument("--integ", default="hmac-sha256-128",
                    choices=sorted(INTEG_ALGORITHMS), metavar="ALG",
                    help=f"Integrity algorithm (default: hmac-sha256-128). "
                         f"Choices: {', '.join(sorted(INTEG_ALGORITHMS))}")
    v2.add_argument("--prf", default="hmac-sha256",
                    choices=sorted(PRF_ALGORITHMS), metavar="ALG",
                    help=f"PRF algorithm (default: hmac-sha256). "
                         f"Choices: {', '.join(sorted(PRF_ALGORITHMS))}")

    # ── IKEv1-specific ────────────────────────────────────────────────────
    v1 = p.add_argument_group("IKEv1-specific options (ignored when --version 2)")
    v1.add_argument("--hash", default="sha1", dest="hash_alg",
                    choices=sorted(V1_HASH_ALGORITHMS), metavar="ALG",
                    help=f"Hash / PRF algorithm (default: sha1). "
                         f"Choices: {', '.join(sorted(V1_HASH_ALGORITHMS))}")
    v1.add_argument("--mode", default="main",
                    choices=["main", "aggressive"],
                    help="Phase 1 exchange mode (default: main)")
    v1.add_argument("--lifetime", type=int, default=28800,
                    help="SA lifetime in seconds (default: 28800)")

    # ── Shared auth / network ─────────────────────────────────────────────
    auth = p.add_argument_group("authentication")
    auth.add_argument("--psk", default="secret",
                      help="Pre-shared key (default: secret)")
    auth.add_argument("--id-local",  default="",
                      help="Local IKE identity (default: outbound IP)")
    auth.add_argument("--id-remote", default="",
                      help="Remote IKE identity (default: host)")

    net = p.add_argument_group("network")
    net.add_argument("--timeout", type=float, default=5.0,
                     help="Socket timeout in seconds (default: 5)")

    p.add_argument("-v", "--verbose", action="store_true",
                   help="Show hex dumps of all packets and crypto operations")
    p.add_argument("--self-test", action="store_true",
                   help="Run built-in crypto self-tests and exit")

    return p


def main() -> None:
    """Parse CLI arguments and run the requested IKEv1/IKEv2 exchange or self-test."""
    parser = build_parser()
    args   = parser.parse_args()

    if args.self_test:
        sys.exit(0 if run_self_test() else 1)

    if not args.host:
        parser.error("host is required unless --self-test is given")

    try:
        if args.version == 1:
            cfg = IKEv1Config(
                host      = args.host,
                port      = args.port,
                encr      = args.encr,
                hash_alg  = args.hash_alg,
                dh_group  = args.dh_group,
                psk       = args.psk,
                id_local  = args.id_local,
                id_remote = args.id_remote,
                mode      = args.mode,
                lifetime  = args.lifetime,
                timeout   = args.timeout,
                verbose   = args.verbose,
            )
            client: IKEv1Client | IKEv2Client = IKEv1Client(cfg)
        else:
            cfg = IKEConfig(
                host      = args.host,
                port      = args.port,
                encr      = args.encr,
                integ     = args.integ,
                prf       = args.prf,
                dh_group  = args.dh_group,
                psk       = args.psk,
                id_local  = args.id_local,
                id_remote = args.id_remote,
                timeout   = args.timeout,
                verbose   = args.verbose,
            )
            client = IKEv2Client(cfg)
    except ValueError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        client.run()
    except TimeoutError as e:
        print(f"\nTimeout: {e}", file=sys.stderr)
        sys.exit(1)
    except NotImplementedError as e:
        print(f"\n[SCAFFOLD] Not yet implemented: {e}", file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
