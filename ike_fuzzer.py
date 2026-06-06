#!/usr/bin/env python3
"""
IKEv2 protocol fuzzer — Milestone 5.

Builds a valid IKE_SA_INIT packet, then applies structured mutations
(header, SA, KE, nonce, payload-chain, truncation, random) to probe how
a responder handles malformed inputs.

Usage:
    python3 ike_fuzzer.py <host> [options]

Examples:
    python3 ike_fuzzer.py 10.0.0.1
    python3 ike_fuzzer.py 10.0.0.1 --strategy header,sa,ke --rounds 0
    python3 ike_fuzzer.py 10.0.0.1 --rounds 50 --report findings.json -v
"""

import argparse
import dataclasses
import json
import os
import random
import socket
import struct
import sys
import textwrap
import time
from typing import Optional

from ike_client import (
    IKEv2Client, IKEConfig, Logger, LogLevel,
    EXCHANGE_IKE_SA_INIT, EXCHANGE_IKE_AUTH,
    FLAG_INITIATOR, FLAG_RESPONSE,
    PAYLOAD_SA, PAYLOAD_KE, PAYLOAD_NONCE, PAYLOAD_NOTIFY,
    PAYLOAD_NAMES, PAYLOAD_NONE,
    PROTO_IKE, PROTO_AH, PROTO_ESP,
    TRANSFORM_TYPE_ENCR, TRANSFORM_TYPE_PRF, TRANSFORM_TYPE_INTEG, TRANSFORM_TYPE_DH,
    NOTIFY_NO_PROPOSAL_CHOSEN, NOTIFY_INVALID_KE_PAYLOAD,
    _hex_dump,
)

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

VERDICTS = ("accepted", "rejected", "timeout", "interesting", "malformed")

@dataclasses.dataclass
class FuzzCase:
    seq:         int
    name:        str           # kebab-case identifier
    category:    str           # header | sa | ke | nonce | payload | truncate | random
    description: str
    pkt:         bytes
    expected:    str           # "timeout" | "rejected" | "accepted" | "any"
    mutations:   list          = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class FuzzResult:
    case:         FuzzCase
    response:     Optional[bytes]
    elapsed_ms:   float
    verdict:      str          # accepted / rejected / timeout / interesting / malformed
    notify_type:  Optional[int]
    notes:        str

    @property
    def interesting(self) -> bool:
        """True when an accepted or interesting verdict was not expected by the test case."""
        return self.verdict in ("interesting", "accepted") and self.case.expected != "accepted"

    def to_dict(self) -> dict:
        """Serialise the result to a plain dict suitable for JSON output."""
        return {
            "seq":         self.case.seq,
            "name":        self.case.name,
            "category":    self.case.category,
            "description": self.case.description,
            "pkt_len":     len(self.case.pkt),
            "mutations":   self.case.mutations,
            "expected":    self.case.expected,
            "verdict":     self.verdict,
            "notify_type": self.notify_type,
            "notes":       self.notes,
            "elapsed_ms":  round(self.elapsed_ms, 2),
            "interesting": self.interesting,
        }


# ---------------------------------------------------------------------------
# Low-level packet helpers
# ---------------------------------------------------------------------------

def _mutate(pkt: bytes, offset: int, new_bytes: bytes) -> bytes:
    """Return a copy of `pkt` with `new_bytes` spliced in at `offset`."""
    return pkt[:offset] + new_bytes + pkt[offset + len(new_bytes):]


def _set_u8(pkt: bytes, offset: int, val: int) -> bytes:
    """Return a copy of `pkt` with a single byte overwritten at `offset`."""
    return _mutate(pkt, offset, bytes([val & 0xFF]))


def _set_u16be(pkt: bytes, offset: int, val: int) -> bytes:
    """Return a copy of `pkt` with a big-endian uint16 overwritten at `offset`."""
    return _mutate(pkt, offset, struct.pack("!H", val & 0xFFFF))


def _set_u32be(pkt: bytes, offset: int, val: int) -> bytes:
    """Return a copy of `pkt` with a big-endian uint32 overwritten at `offset`."""
    return _mutate(pkt, offset, struct.pack("!I", val & 0xFFFFFFFF))


def _craft_transform(t_type: int, t_id: int, attrs: bytes = b"", last: bool = False) -> bytes:
    """Build a raw IKEv2 Transform substructure (RFC 7296 §3.3.2)."""
    more   = 0 if last else 3
    length = 8 + len(attrs)
    return struct.pack("!BBHBBH", more, 0, length, t_type, 0, t_id) + attrs


def _key_len_attr(bits: int) -> bytes:
    """Build a Key Length (type 14) transform attribute for symmetric ciphers."""
    return struct.pack("!HH", 0x800E, bits)


def _craft_proposal(proto_id: int, xforms: list[bytes], spi: bytes = b"") -> bytes:
    """Build a raw IKEv2 Proposal substructure containing the given transforms."""
    trans_bytes = b"".join(xforms)
    prop_len    = 8 + len(spi) + len(trans_bytes)
    return (
        struct.pack("!BBHBBBB", 0, 0, prop_len, 1, proto_id, len(spi), len(xforms))
        + spi
        + trans_bytes
    )


def _craft_sa_payload(next_payload: int, proposal_bytes: bytes,
                      critical: bool = False) -> bytes:
    """Wrap a serialised proposal in an SA payload generic header."""
    crit = 0x80 if critical else 0
    plen = 4 + len(proposal_bytes)
    return struct.pack("!BBH", next_payload, crit, plen) + proposal_bytes


def _craft_ke_payload(next_payload: int, group: int, pubkey: bytes) -> bytes:
    """Build a KE payload: generic header + DH group number + reserved + public key."""
    body = struct.pack("!HH", group, 0) + pubkey
    return struct.pack("!BBH", next_payload, 0, 4 + len(body)) + body


def _craft_nonce_payload(next_payload: int, nonce: bytes) -> bytes:
    """Build a Nonce payload: generic header + raw nonce bytes."""
    return struct.pack("!BBH", next_payload, 0, 4 + len(nonce)) + nonce


def _craft_unknown_payload(next_payload: int, data: bytes,
                            ptype: int = 200) -> bytes:
    """Appended to the chain using the *previous* payload's next_payload field."""
    body = struct.pack("!BBH", next_payload, 0, 4 + len(data)) + data
    return body


# ---------------------------------------------------------------------------
# Base packet builder
# ---------------------------------------------------------------------------

def build_base_packet(cfg: IKEConfig) -> tuple[bytes, IKEv2Client]:
    """
    Build a valid IKE_SA_INIT packet using the normal client machinery.
    Returns (packet_bytes, client_with_state) without sending anything.
    """
    c = IKEv2Client(cfg)
    c.log.min_level = LogLevel.ERROR
    c._generate_dh_keypair()
    c.nonce_i = os.urandom(32)

    nonce_pld = c._build_nonce_payload(PAYLOAD_NONE, c.nonce_i)
    ke_pld    = c._build_ke_payload(PAYLOAD_NONCE)
    sa_pld    = c._build_sa_payload(PAYLOAD_KE)
    payloads  = sa_pld + ke_pld + nonce_pld
    hdr = c._build_ike_header(
        exch_type=EXCHANGE_IKE_SA_INIT,
        flags=FLAG_INITIATOR,
        msg_id=0,
        next_payload=PAYLOAD_SA,
        total_len=28 + len(payloads),
    )
    pkt = hdr + payloads
    c.msg1_bytes = pkt
    return pkt, c


# ---------------------------------------------------------------------------
# Mutation generators
# ---------------------------------------------------------------------------

def gen_header_mutations(base: bytes) -> list[FuzzCase]:
    """Mutate each field of the 28-byte IKE fixed header."""
    cases: list[FuzzCase] = []
    real_len = struct.unpack("!I", base[24:28])[0]

    specs = [
        # (name, description, mutated_pkt, expected)
        ("exch-type-ike-auth",  "Exchange type = IKE_AUTH (35) not IKE_SA_INIT",
         _set_u8(base, 18, EXCHANGE_IKE_AUTH), "timeout"),
        ("exch-type-zero",      "Exchange type = 0 (reserved)",
         _set_u8(base, 18, 0),                 "timeout"),
        ("exch-type-255",       "Exchange type = 255 (unknown)",
         _set_u8(base, 18, 255),               "timeout"),
        ("flags-zero",          "Flags = 0x00 (no initiator bit)",
         _set_u8(base, 19, 0x00),              "any"),
        ("flags-all",           "Flags = 0xFF (all bits set)",
         _set_u8(base, 19, 0xFF),              "any"),
        ("flags-response",      "Response flag set (0x20) in request",
         _set_u8(base, 19, 0x20),              "timeout"),
        ("version-ikev1",       "Version = 0x10 (IKEv1 major/minor)",
         _set_u8(base, 17, 0x10),              "any"),
        ("version-zero",        "Version = 0x00",
         _set_u8(base, 17, 0x00),              "timeout"),
        ("version-ff",          "Version = 0xFF",
         _set_u8(base, 17, 0xFF),              "timeout"),
        ("msg-id-one",          "Message ID = 1 (must be 0 for IKE_SA_INIT)",
         _set_u32be(base, 20, 1),              "any"),
        ("msg-id-max",          "Message ID = 0xFFFFFFFF",
         _set_u32be(base, 20, 0xFFFFFFFF),     "timeout"),
        ("length-zero",         "Total length field = 0",
         _set_u32be(base, 24, 0),              "timeout"),
        ("length-minus-one",    "Total length = actual − 1 (truncated field)",
         _set_u32be(base, 24, real_len - 1),   "any"),
        ("length-plus-one",     "Total length = actual + 1 (length > available data)",
         _set_u32be(base, 24, real_len + 1),   "any"),
        ("length-max",          "Total length = 0xFFFFFFFF",
         _set_u32be(base, 24, 0xFFFFFFFF),     "timeout"),
        ("spi-i-zeros",         "SPIi = all zeros (invalid initiator SPI)",
         _mutate(base, 0, b"\x00" * 8),        "any"),
        ("spi-r-nonzero",       "SPIr non-zero in request (must be 0)",
         _mutate(base, 8, b"\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF"), "any"),
    ]
    for name, desc, pkt, exp in specs:
        cases.append(FuzzCase(0, name, "header", desc, pkt, exp))
    return cases


def gen_sa_mutations(base: bytes, cfg: IKEConfig) -> list[FuzzCase]:
    """Mutate the SA payload contents: transforms, proto, lengths."""
    cases: list[FuzzCase] = []
    encr  = cfg.encr_alg
    prf   = cfg.prf_alg
    integ = cfg.integ_alg
    dh    = cfg.dh_group

    # Helpers to reconstruct a packet with a custom SA payload replacing the original
    sa_len = struct.unpack("!H", base[30:32])[0]   # SA generic header length at offset 28

    def _replace_sa(sa_bytes: bytes) -> bytes:
        """Splice `sa_bytes` in place of the original SA payload and patch total length."""
        # SA starts at byte 28; next payload of SA header is the old value
        # Preserve the next_payload chain by keeping the next field intact from the old SA header
        rest = base[28 + sa_len:]   # KE + Nonce payloads (unchanged)
        new_total = 28 + len(sa_bytes) + len(rest)
        new_pkt = _set_u32be(base[:28], 24, new_total) + sa_bytes + rest
        return new_pkt

    # Reconstruct the "normal" set of transforms for reference
    def _normal_xforms(override_dh: Optional[int] = None) -> list[bytes]:
        """Return the reference transform list for the configured algorithm set."""
        xf: list[bytes] = []
        kl = _key_len_attr(encr.key_len) if encr.transform_id != 3 else b""
        xf.append(_craft_transform(TRANSFORM_TYPE_ENCR, encr.transform_id, kl))
        xf.append(_craft_transform(TRANSFORM_TYPE_PRF, prf.transform_id))
        if integ:
            xf.append(_craft_transform(TRANSFORM_TYPE_INTEG, integ.transform_id))
        xf.append(_craft_transform(TRANSFORM_TYPE_DH, override_dh or dh, last=True))
        xf[-1] = _craft_transform(TRANSFORM_TYPE_DH, override_dh or dh, last=True)
        return xf

    # 1. No transforms
    prop0 = struct.pack("!BBHBBBB", 0, 0, 8, 1, PROTO_IKE, 0, 0)
    cases.append(FuzzCase(0, "sa-no-transforms", "sa",
                          "SA proposal with 0 transforms",
                          _replace_sa(_craft_sa_payload(PAYLOAD_KE, prop0)),
                          "rejected"))

    # 2. Unknown ENCR transform ID
    xf_bad_encr = [_craft_transform(TRANSFORM_TYPE_ENCR, 255)] + _normal_xforms()[1:]
    xf_bad_encr[-1] = _craft_transform(TRANSFORM_TYPE_DH, dh, last=True)
    cases.append(FuzzCase(0, "sa-unknown-encr", "sa",
                          "SA ENCR transform ID = 255 (unknown)",
                          _replace_sa(_craft_sa_payload(PAYLOAD_KE,
                              _craft_proposal(PROTO_IKE, xf_bad_encr))),
                          "rejected"))

    # 3. DH mismatch: propose DH=2 in SA but send KE for actual DH group
    alt_dh = 2 if dh != 2 else 5
    xf_dh_mis = _normal_xforms(override_dh=alt_dh)
    cases.append(FuzzCase(0, "sa-dh-mismatch", "sa",
                          f"SA proposes DH={alt_dh} but KE carries DH={dh}",
                          _replace_sa(_craft_sa_payload(PAYLOAD_KE,
                              _craft_proposal(PROTO_IKE, xf_dh_mis))),
                          "rejected"))

    # 4. Protocol = AH instead of IKE
    xf_norm = _normal_xforms()
    cases.append(FuzzCase(0, "sa-proto-ah", "sa",
                          "SA proposal protocol = AH (2) instead of IKE (1)",
                          _replace_sa(_craft_sa_payload(PAYLOAD_KE,
                              _craft_proposal(PROTO_AH, xf_norm))),
                          "rejected"))

    # 5. SA payload generic header length = 0
    sa_len_0 = _set_u16be(base[28:28+sa_len+len(base)-28-sa_len], 2, 0)
    cases.append(FuzzCase(0, "sa-length-zero", "sa",
                          "SA payload generic header length field = 0",
                          _set_u16be(base, 30, 0),
                          "timeout"))

    # 6. Duplicate ENCR transform
    kl = _key_len_attr(encr.key_len) if encr.transform_id != 3 else b""
    xf_dup = [
        _craft_transform(TRANSFORM_TYPE_ENCR, encr.transform_id, kl),
        _craft_transform(TRANSFORM_TYPE_ENCR, encr.transform_id, kl),
        _craft_transform(TRANSFORM_TYPE_PRF, prf.transform_id),
    ]
    if integ:
        xf_dup.append(_craft_transform(TRANSFORM_TYPE_INTEG, integ.transform_id))
    xf_dup.append(_craft_transform(TRANSFORM_TYPE_DH, dh, last=True))
    cases.append(FuzzCase(0, "sa-dup-encr", "sa",
                          "SA proposal has two identical ENCR transforms",
                          _replace_sa(_craft_sa_payload(PAYLOAD_KE,
                              _craft_proposal(PROTO_IKE, xf_dup))),
                          "any"))

    # 7. Unknown transform type (250)
    xf_unk = _normal_xforms()[:-1] + [
        _craft_transform(250, 1),
        _craft_transform(TRANSFORM_TYPE_DH, dh, last=True),
    ]
    cases.append(FuzzCase(0, "sa-unknown-transform-type", "sa",
                          "SA transform type = 250 (unknown type)",
                          _replace_sa(_craft_sa_payload(PAYLOAD_KE,
                              _craft_proposal(PROTO_IKE, xf_unk))),
                          "any"))

    # 8. SA critical bit set
    xf_norm2 = _normal_xforms()
    cases.append(FuzzCase(0, "sa-critical-bit", "sa",
                          "SA payload generic header has critical bit set",
                          _replace_sa(_craft_sa_payload(PAYLOAD_KE,
                              _craft_proposal(PROTO_IKE, xf_norm2), critical=True)),
                          "any"))

    # 9. Missing PRF transform (RFC 7296 §3.3.2 mandates PRF in IKE_SA_INIT)
    kl = _key_len_attr(encr.key_len) if encr.transform_id != 3 else b""
    xf_no_prf = [_craft_transform(TRANSFORM_TYPE_ENCR, encr.transform_id, kl)]
    if integ:
        xf_no_prf.append(_craft_transform(TRANSFORM_TYPE_INTEG, integ.transform_id))
    xf_no_prf.append(_craft_transform(TRANSFORM_TYPE_DH, dh, last=True))
    cases.append(FuzzCase(0, "sa-missing-prf", "sa",
                          "SA proposal omits mandatory PRF transform",
                          _replace_sa(_craft_sa_payload(PAYLOAD_KE,
                              _craft_proposal(PROTO_IKE, xf_no_prf))),
                          "rejected"))

    # 10. Missing DH transform (KE payload present but no agreed group)
    kl = _key_len_attr(encr.key_len) if encr.transform_id != 3 else b""
    xf_no_dh = [_craft_transform(TRANSFORM_TYPE_ENCR, encr.transform_id, kl),
                _craft_transform(TRANSFORM_TYPE_PRF, prf.transform_id)]
    if integ:
        xf_no_dh.append(_craft_transform(TRANSFORM_TYPE_INTEG, integ.transform_id, last=True))
    else:
        xf_no_dh[-1] = _craft_transform(TRANSFORM_TYPE_PRF, prf.transform_id, last=True)
    cases.append(FuzzCase(0, "sa-missing-dh", "sa",
                          "SA proposal omits DH transform (KE payload still present)",
                          _replace_sa(_craft_sa_payload(PAYLOAD_KE,
                              _craft_proposal(PROTO_IKE, xf_no_dh))),
                          "rejected"))

    # 11. Two proposals: valid first + second with unrecognised DH group 999
    prop1      = _craft_proposal(PROTO_IKE, _normal_xforms())
    prop1_more = _set_u8(prop1, 0, 2)          # byte 0 = last/more; 2 = more proposals follow
    prop2      = _craft_proposal(PROTO_IKE, _normal_xforms(override_dh=999))
    prop2_n2   = _set_u8(prop2, 4, 2)          # proposal number field = 2
    cases.append(FuzzCase(0, "sa-two-proposals", "sa",
                          "SA two proposals: valid first, DH-999 second",
                          _replace_sa(_craft_sa_payload(PAYLOAD_KE,
                              prop1_more + prop2_n2)),
                          "any"))

    # 12. ENCR key length attribute = 0
    kl_zero = struct.pack("!HH", 0x800E, 0)
    xf_kl0 = [_craft_transform(TRANSFORM_TYPE_ENCR, encr.transform_id, kl_zero),
               _craft_transform(TRANSFORM_TYPE_PRF, prf.transform_id)]
    if integ:
        xf_kl0.append(_craft_transform(TRANSFORM_TYPE_INTEG, integ.transform_id))
    xf_kl0.append(_craft_transform(TRANSFORM_TYPE_DH, dh, last=True))
    cases.append(FuzzCase(0, "sa-key-len-zero", "sa",
                          "SA ENCR transform key length attribute = 0 bits",
                          _replace_sa(_craft_sa_payload(PAYLOAD_KE,
                              _craft_proposal(PROTO_IKE, xf_kl0))),
                          "rejected"))

    # 13. ENCR key length attribute = 65535
    kl_huge = struct.pack("!HH", 0x800E, 65535)
    xf_klhuge = [_craft_transform(TRANSFORM_TYPE_ENCR, encr.transform_id, kl_huge),
                 _craft_transform(TRANSFORM_TYPE_PRF, prf.transform_id)]
    if integ:
        xf_klhuge.append(_craft_transform(TRANSFORM_TYPE_INTEG, integ.transform_id))
    xf_klhuge.append(_craft_transform(TRANSFORM_TYPE_DH, dh, last=True))
    cases.append(FuzzCase(0, "sa-key-len-huge", "sa",
                          "SA ENCR transform key length attribute = 65535 bits",
                          _replace_sa(_craft_sa_payload(PAYLOAD_KE,
                              _craft_proposal(PROTO_IKE, xf_klhuge))),
                          "rejected"))

    return cases


def gen_ke_mutations(base: bytes, cfg: IKEConfig) -> list[FuzzCase]:
    """Mutate the KE payload."""
    cases: list[FuzzCase] = []
    sa_len = struct.unpack("!H", base[30:32])[0]
    ke_off = 28 + sa_len                            # byte offset of KE generic header
    ke_len = struct.unpack("!H", base[ke_off+2:ke_off+4])[0]
    pubkey_len = ke_len - 8                         # subtract header(4) + group(2) + res(2)
    dh = cfg.dh_group

    def _replace_ke(ke_bytes: bytes) -> bytes:
        """Splice `ke_bytes` in place of the original KE payload and patch total length."""
        before  = base[:ke_off]
        after   = base[ke_off + ke_len:]
        new_total = len(before) + len(ke_bytes) + len(after)
        return _set_u32be(before, 24, new_total) + ke_bytes + after

    specs = [
        ("ke-group-zero",     "KE DH group = 0 (reserved)",
         _craft_ke_payload(PAYLOAD_NONCE, 0, os.urandom(pubkey_len)), "rejected"),
        ("ke-group-unknown",  "KE DH group = 1023 (unknown)",
         _craft_ke_payload(PAYLOAD_NONCE, 1023, os.urandom(pubkey_len)), "rejected"),
        ("ke-pubkey-zeros",   "KE public key = all zeros",
         _craft_ke_payload(PAYLOAD_NONCE, dh, bytes(pubkey_len)), "any"),
        ("ke-pubkey-ff",      "KE public key = all 0xFF",
         _craft_ke_payload(PAYLOAD_NONCE, dh, bytes([0xFF] * pubkey_len)), "any"),
        ("ke-pubkey-empty",   "KE payload with 0-byte public key",
         _craft_ke_payload(PAYLOAD_NONCE, dh, b""), "rejected"),
        ("ke-pubkey-one-byte","KE public key = single 0x01 byte",
         _craft_ke_payload(PAYLOAD_NONCE, dh, b"\x01"), "rejected"),
        ("ke-pubkey-half",    "KE public key = half expected length",
         _craft_ke_payload(PAYLOAD_NONCE, dh, os.urandom(pubkey_len // 2)), "rejected"),
        ("ke-pubkey-short-1", "KE public key one byte shorter than expected",
         _craft_ke_payload(PAYLOAD_NONCE, dh, os.urandom(pubkey_len - 1)), "rejected"),
    ]
    for name, desc, ke_pld, exp in specs:
        cases.append(FuzzCase(0, name, "ke", desc, _replace_ke(ke_pld), exp))
    return cases


def gen_nonce_mutations(base: bytes, cfg: IKEConfig) -> list[FuzzCase]:
    """Mutate the Nonce payload."""
    cases: list[FuzzCase] = []
    sa_len = struct.unpack("!H", base[30:32])[0]
    ke_off = 28 + sa_len
    ke_len = struct.unpack("!H", base[ke_off+2:ke_off+4])[0]
    ni_off = ke_off + ke_len     # byte offset of Nonce generic header

    def _replace_nonce(nonce_bytes: bytes) -> bytes:
        """Splice `nonce_bytes` in place of the original Nonce payload and patch total length."""
        before = base[:ni_off]
        new_total = len(before) + len(nonce_bytes)
        return _set_u32be(before, 24, new_total) + nonce_bytes

    specs = [
        ("nonce-empty",   "Nonce payload with 0 bytes of nonce data",
         _craft_nonce_payload(PAYLOAD_NONE, b""), "any"),
        ("nonce-1byte",   "Nonce = 1 byte (RFC minimum is 16)",
         _craft_nonce_payload(PAYLOAD_NONE, b"\x42"), "any"),
        ("nonce-zeros",   "Nonce = 32 zero bytes",
         _craft_nonce_payload(PAYLOAD_NONE, bytes(32)), "any"),
        ("nonce-huge",    "Nonce = 2048 bytes",
         _craft_nonce_payload(PAYLOAD_NONE, os.urandom(2048)), "any"),
        ("nonce-all-ff",  "Nonce = 32 bytes of 0xFF",
         _craft_nonce_payload(PAYLOAD_NONE, bytes([0xFF] * 32)), "any"),
    ]
    for name, desc, ni_pld, exp in specs:
        cases.append(FuzzCase(0, name, "nonce", desc, _replace_nonce(ni_pld), exp))
    return cases


def gen_payload_chain_mutations(base: bytes) -> list[FuzzCase]:
    """Corrupt payload-chain next_payload pointers and add unknown payloads."""
    cases: list[FuzzCase] = []
    sa_len = struct.unpack("!H", base[30:32])[0]
    ke_off = 28 + sa_len
    ke_len = struct.unpack("!H", base[ke_off+2:ke_off+4])[0]
    ni_off = ke_off + ke_len

    # 1. IKE header next_payload → unknown type
    cases.append(FuzzCase(0, "chain-nxt-unknown", "payload",
                          "IKE header next_payload = 200 (unknown type)",
                          _set_u8(base, 16, 200), "any"))

    # 2. SA next_payload → NONCE (skips KE)
    cases.append(FuzzCase(0, "chain-sa-skips-ke", "payload",
                          "SA next_payload = NONCE (40), skipping KE",
                          _set_u8(base, 28, PAYLOAD_NONCE), "any"))

    # 3. Critical bit on SA payload
    cases.append(FuzzCase(0, "chain-sa-critical", "payload",
                          "SA payload critical bit set",
                          _set_u8(base, 29, 0x80), "any"))

    # 4. Append unknown payload type 200 after nonce
    unk_pld   = struct.pack("!BBH", PAYLOAD_NONE, 0, 8) + b"\xDE\xAD\xBE\xEF"
    extended  = base[:-1]   # trim last byte of nonce (its next_payload)
    # Properly: update the nonce's next_payload field to 200
    ni_off    = ke_off + ke_len
    patched   = _set_u8(base, ni_off, 200)   # nonce next_payload = 200
    appended  = patched + unk_pld
    new_total = struct.unpack("!I", base[24:28])[0] + len(unk_pld)
    appended  = _set_u32be(appended, 24, new_total)
    cases.append(FuzzCase(0, "chain-unknown-extra", "payload",
                          "Append unknown payload (type=200) after Nonce",
                          appended, "any"))

    # 5. No payloads: IKE header only, next_payload = 0
    hdr_only = base[:28]
    hdr_only = _set_u8(hdr_only, 16, 0)         # next_payload = None
    hdr_only = _set_u32be(hdr_only, 24, 28)     # length = 28
    cases.append(FuzzCase(0, "no-payloads", "payload",
                          "IKE header only, no payloads (next_payload=0)",
                          hdr_only, "any"))

    # 6. SA payload length = 0xFFFF (claims to be huge)
    cases.append(FuzzCase(0, "sa-length-ffff", "payload",
                          "SA payload length field = 0xFFFF",
                          _set_u16be(base, 30, 0xFFFF), "timeout"))

    # Payload slice helpers
    sa_bytes = base[28:ke_off]          # SA payload (next_payload = KE)
    ke_bytes = base[ke_off:ni_off]      # KE payload (next_payload = Nonce)
    ni_bytes = base[ni_off:]            # Nonce payload (next_payload = None)

    def _rebuild(body: bytes) -> bytes:
        """Assemble a new IKE packet from a raw payload block, fixing total length."""
        return _set_u32be(base[:28], 24, 28 + len(body)) + body

    # 7. SA missing — IKE header next_payload jumps straight to KE
    new_hdr = _set_u8(base[:28], 16, PAYLOAD_KE)
    ke_ni   = base[ke_off:]
    cases.append(FuzzCase(0, "chain-sa-missing", "payload",
                          "SA payload omitted; chain starts at KE",
                          _set_u32be(new_hdr, 24, 28 + len(ke_ni)) + ke_ni,
                          "rejected"))

    # 8. KE missing — SA next_payload points directly to Nonce
    sa_skip_ke = _set_u8(sa_bytes, 0, PAYLOAD_NONCE)
    cases.append(FuzzCase(0, "chain-ke-missing", "payload",
                          "KE payload omitted; SA next_payload = Nonce",
                          _rebuild(sa_skip_ke + ni_bytes),
                          "rejected"))

    # 9. Nonce missing — KE next_payload = None, packet ends after KE
    ke_no_ni = _set_u8(ke_bytes, 0, PAYLOAD_NONE)
    cases.append(FuzzCase(0, "chain-nonce-missing", "payload",
                          "Nonce payload omitted; KE next_payload = None",
                          _rebuild(sa_bytes + ke_no_ni),
                          "rejected"))

    # 10. Duplicate SA — two identical SA payloads before KE
    sa_1 = _set_u8(sa_bytes, 0, PAYLOAD_SA)    # first SA → second SA
    sa_2 = sa_bytes                             # second SA → KE (unchanged)
    cases.append(FuzzCase(0, "chain-dup-sa", "payload",
                          "Two identical SA payloads in chain",
                          _rebuild(sa_1 + sa_2 + ke_bytes + ni_bytes),
                          "any"))

    # 11. Duplicate KE — two identical KE payloads
    ke_1 = _set_u8(ke_bytes, 0, PAYLOAD_KE)    # first KE → second KE
    ke_2 = ke_bytes                             # second KE → Nonce (unchanged)
    cases.append(FuzzCase(0, "chain-dup-ke", "payload",
                          "Two identical KE payloads in chain",
                          _rebuild(sa_bytes + ke_1 + ke_2 + ni_bytes),
                          "any"))

    # 12. Duplicate Nonce — two identical Nonce payloads
    ni_1 = _set_u8(ni_bytes, 0, PAYLOAD_NONCE)  # first Nonce → second Nonce
    ni_2 = _set_u8(ni_bytes, 0, PAYLOAD_NONE)   # second Nonce → None
    cases.append(FuzzCase(0, "chain-dup-nonce", "payload",
                          "Two identical Nonce payloads in chain",
                          _rebuild(sa_bytes + ke_bytes + ni_1 + ni_2),
                          "any"))

    # 13. Payload order swapped — SA, Nonce, KE (Nonce before KE)
    sa_to_ni  = _set_u8(sa_bytes,  0, PAYLOAD_NONCE)  # SA → Nonce
    ni_to_ke  = _set_u8(ni_bytes,  0, PAYLOAD_KE)     # Nonce → KE
    ke_to_end = _set_u8(ke_bytes,  0, PAYLOAD_NONE)   # KE → None
    cases.append(FuzzCase(0, "chain-order-sa-ni-ke", "payload",
                          "Payload order: SA, Nonce, KE (non-standard ordering)",
                          _rebuild(sa_to_ni + ni_to_ke + ke_to_end),
                          "any"))

    return cases


def gen_truncation_cases(base: bytes) -> list[FuzzCase]:
    """Send the packet truncated at various byte offsets."""
    cases: list[FuzzCase] = []
    length = len(base)
    offsets = [4, 20, 27, 28, 32, 60, length // 4, length // 2,
               length - 4, length - 1]
    for off in sorted(set(o for o in offsets if 1 <= o < length)):
        cases.append(FuzzCase(0, f"trunc-at-{off}", "truncate",
                              f"Packet truncated to {off} bytes (of {length})",
                              base[:off], "timeout"))
    return cases


def _label_sa_body(pkt: bytes, start: int, end: int, labels: dict[int, str]) -> None:
    """Fill `labels` with field descriptions for bytes inside an SA payload body."""
    XFORM_TYPE_NAMES = {1: "ENCR", 2: "PRF", 3: "INTEG", 4: "DH", 5: "ESN"}
    off      = start
    prop_num = 1
    while off + 8 <= end:
        prop_len = struct.unpack("!H", pkt[off + 2:off + 4])[0]
        if prop_len < 8 or off + prop_len > end:
            break
        p = f"SA-prop{prop_num}"
        labels[off]     = f"{p} last/more"
        labels[off + 1] = f"{p} reserved"
        labels[off + 2] = f"{p} length[0]"
        labels[off + 3] = f"{p} length[1]"
        labels[off + 4] = f"{p} number"
        labels[off + 5] = f"{p} protocol-id"
        labels[off + 6] = f"{p} spi-size"
        labels[off + 7] = f"{p} num-transforms"
        spi_size   = pkt[off + 6]
        num_xforms = pkt[off + 7]
        xf_off = off + 8 + spi_size
        for xi in range(num_xforms):
            if xf_off + 8 > off + prop_len:
                break
            xf_len = struct.unpack("!H", pkt[xf_off + 2:xf_off + 4])[0]
            if xf_len < 8:
                break
            tname = XFORM_TYPE_NAMES.get(pkt[xf_off + 4], f"type{pkt[xf_off + 4]}")
            x = f"SA-xform{xi + 1}({tname})"
            labels[xf_off]     = f"{x} last/more"
            labels[xf_off + 1] = f"{x} reserved"
            labels[xf_off + 2] = f"{x} length[0]"
            labels[xf_off + 3] = f"{x} length[1]"
            labels[xf_off + 4] = f"{x} type"
            labels[xf_off + 5] = f"{x} reserved"
            labels[xf_off + 6] = f"{x} id[0]"
            labels[xf_off + 7] = f"{x} id[1]"
            for ai in range(xf_off + 8, xf_off + xf_len):
                labels[ai] = f"{x} attr[{ai - xf_off - 8}]"
            xf_off += xf_len
        off += prop_len
        prop_num += 1


def _label_offsets(pkt: bytes) -> dict[int, str]:
    """
    Return a mapping of byte offset → human-readable field name for an IKE_SA_INIT packet.

    Walks the IKE fixed header and each payload in the chain, assigning a semantic
    label (e.g. 'IKE-hdr exchange-type', 'KE pubkey[3]', 'SA-xform1(ENCR) id[0]')
    to every byte.  Used by gen_random_mutations to annotate flipped bytes.
    """
    labels: dict[int, str] = {}
    if len(pkt) < 28:
        return labels

    for i in range(8): labels[i]      = f"IKE-hdr SPIi[{i}]"
    for i in range(8): labels[8 + i]  = f"IKE-hdr SPIr[{i}]"
    labels[16] = "IKE-hdr next-payload"
    labels[17] = "IKE-hdr version"
    labels[18] = "IKE-hdr exchange-type"
    labels[19] = "IKE-hdr flags"
    for i in range(4): labels[20 + i] = f"IKE-hdr msg-id[{i}]"
    for i in range(4): labels[24 + i] = f"IKE-hdr total-len[{i}]"

    cur_type = pkt[16]
    off = 28
    while cur_type != 0 and off + 4 <= len(pkt):
        next_type = pkt[off]
        plen = struct.unpack("!H", pkt[off + 2:off + 4])[0]
        if plen < 4 or off + plen > len(pkt):
            break
        pname = PAYLOAD_NAMES.get(cur_type, f"payload{cur_type}")
        labels[off]     = f"{pname} next-payload"
        labels[off + 1] = f"{pname} critical/flags"
        labels[off + 2] = f"{pname} length[0]"
        labels[off + 3] = f"{pname} length[1]"
        body_start = off + 4
        body_end   = off + plen
        if cur_type == PAYLOAD_SA:       # 33
            _label_sa_body(pkt, body_start, body_end, labels)
        elif cur_type == PAYLOAD_KE:     # 34
            if body_start + 4 <= body_end:
                labels[body_start]     = "KE DH-group[0]"
                labels[body_start + 1] = "KE DH-group[1]"
                labels[body_start + 2] = "KE reserved[0]"
                labels[body_start + 3] = "KE reserved[1]"
                for i in range(body_start + 4, body_end):
                    labels[i] = f"KE pubkey[{i - body_start - 4}]"
        elif cur_type == PAYLOAD_NONCE:  # 40
            for i in range(body_start, body_end):
                labels[i] = f"Nonce data[{i - body_start}]"
        cur_type = next_type
        off += plen
    return labels


def gen_random_mutations(base: bytes, n: int, seed: int) -> list[FuzzCase]:
    """
    Flip 1–4 bytes at random offsets using a fixed seed for reproducibility.

    Each FuzzCase.mutations list contains one dict per flipped byte with keys:
      offset    — byte position in the packet
      field     — human-readable field name (e.g. 'IKE-hdr exchange-type')
      original  — hex value before mutation (e.g. '0x22')
      modified  — hex value after mutation  (e.g. '0x7f')
    """
    labels = _label_offsets(base)
    rng    = random.Random(seed)
    cases: list[FuzzCase] = []
    for i in range(n):
        pkt     = bytearray(base)
        count   = rng.randint(1, 4)
        offsets = [rng.randint(0, len(base) - 1) for _ in range(count)]
        orig_vals = [pkt[off] for off in offsets]          # capture before mutation
        new_vals  = [rng.randint(0, 255) for _ in offsets] # same RNG call sequence as before
        for off, new_val in zip(offsets, new_vals):
            pkt[off] = new_val
        mutations = [
            {
                "offset":   off,
                "field":    labels.get(off, f"byte[{off}]"),
                "original": f"0x{orig:02x}",
                "modified": f"0x{new:02x}",
            }
            for off, orig, new in zip(offsets, orig_vals, new_vals)
        ]
        desc = "Random flip: " + ", ".join(
            f"[{m['offset']} {m['field']}] {m['original']}→{m['modified']}"
            for m in mutations
        )
        cases.append(FuzzCase(0, f"random-{i:03d}", "random", desc, bytes(pkt), "any", mutations))
    return cases


# ---------------------------------------------------------------------------
# Response classification
# ---------------------------------------------------------------------------

KNOWN_NOTIFY: dict[int, str] = {
    1:     "UNSUPPORTED_CRITICAL_PAYLOAD",
    4:     "INVALID_IKE_SPI",
    5:     "INVALID_MAJOR_VERSION",
    7:     "INVALID_SYNTAX",
    11:    "INVALID_MESSAGE_ID",
    14:    "NO_PROPOSAL_CHOSEN",
    17:    "INVALID_KE_PAYLOAD",
    24:    "AUTHENTICATION_FAILED",
    34:    "USE_TRANSPORT_MODE",
    40:    "CHILD_SA_NOT_FOUND",
    16388: "NAT_DETECTION_SOURCE_IP",
    16389: "NAT_DETECTION_DESTINATION_IP",
    16390: "MULTIPLE_AUTH_SUPPORTED",
}


def classify(resp: bytes, spi_i: bytes) -> tuple[str, Optional[int], str]:
    """
    Return (verdict, notify_type, notes) for a received response.

    verdict:
      accepted    — SA_INIT response with assigned SPIr and no error notifies
      rejected    — error Notify (type < 16384) present, OR SPIr=0 with only
                    informational notifies (type ≥ 16384, responder declined
                    without allocating an SPI)
      interesting — valid IKE framing but genuinely ambiguous (e.g. SPIr=0
                    with no notifies at all, wrong exchange type, SPIi mismatch)
      malformed   — fewer than 28 bytes; can't parse IKE header
      (timeout is handled by the caller returning None response)
    """
    if len(resp) < 28:
        return "malformed", None, f"response only {len(resp)}B (< 28)"

    r_spi_i = resp[0:8]
    r_spi_r = resp[8:16]
    r_nxt   = resp[16]
    r_exch  = resp[18]
    r_flags = resp[19]
    r_len   = struct.unpack("!I", resp[24:28])[0]
    is_resp = bool(r_flags & FLAG_RESPONSE)

    notes_parts = []
    if r_spi_i != spi_i:
        notes_parts.append(f"SPIi mismatch ({r_spi_i.hex()} ≠ {spi_i.hex()})")

    # Walk payload chain and collect all Notify types
    notify_types: list[int] = []
    cap = min(r_len, len(resp))
    if cap > 28 and r_nxt != PAYLOAD_NONE:
        body = resp[28:cap]
        cur  = r_nxt
        poff = 0
        while cur != PAYLOAD_NONE and poff + 4 <= len(body):
            nxt  = body[poff]
            plen = struct.unpack("!H", body[poff + 2:poff + 4])[0]
            if plen < 4 or poff + plen > len(body):
                break
            if cur == 41 and plen >= 8:                 # NOTIFY payload
                n_type = struct.unpack("!H", body[poff + 6:poff + 8])[0]
                notify_types.append(n_type)
            poff += plen
            cur   = nxt

    if notify_types:
        notes_parts.append("notify: " + ", ".join(
            KNOWN_NOTIFY.get(t, str(t)) for t in notify_types
        ))

    # Must be a response to our IKE_SA_INIT with our SPIi to be classifiable
    if r_exch == EXCHANGE_IKE_SA_INIT and is_resp and r_spi_i == spi_i:
        error_notifies = [t for t in notify_types if t < 16384]
        if error_notifies:
            # Error notify present → definitively rejected
            primary = min(error_notifies)
            return "rejected", primary, " | ".join(notes_parts)
        elif r_spi_r != b"\x00" * 8:
            # No error, non-zero SPIr → SA offered / accepted
            return "accepted", notify_types[0] if notify_types else None, \
                   " | ".join(notes_parts) or "SA_INIT accepted"
        elif notify_types:
            # SPIr=0, no error notifies, but informational notifies present —
            # the responder declined without assigning an SPI.
            return "rejected", None, " | ".join(notes_parts)
        else:
            # SPIr=0, no notifies at all — genuinely ambiguous.
            notes_parts.append("SPIr=0 with no notifies")
            return "interesting", None, " | ".join(notes_parts)

    if r_exch == EXCHANGE_IKE_SA_INIT and not is_resp:
        notes_parts.append("response flag not set")
        return "interesting", notify_types[0] if notify_types else None, \
               " | ".join(notes_parts)

    if r_exch != EXCHANGE_IKE_SA_INIT:
        notes_parts.append(f"unexpected exchange type {r_exch}")
        return "interesting", None, " | ".join(notes_parts)

    # Catch-all: SPIi mismatch etc.
    return "interesting", notify_types[0] if notify_types else None, \
           " | ".join(notes_parts)


# ---------------------------------------------------------------------------
# Sending
# ---------------------------------------------------------------------------

def send_case(case: FuzzCase, host: str, port: int,
              timeout: float, verbose: bool) -> FuzzResult:
    """Send one fuzz case and return the result."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    t0 = time.monotonic()
    resp: Optional[bytes] = None
    try:
        sock.sendto(case.pkt, (host, port))
        resp, _ = sock.recvfrom(65536)
    except socket.timeout:
        pass
    finally:
        sock.close()
    elapsed_ms = (time.monotonic() - t0) * 1000

    if resp is None:
        result = FuzzResult(case, None, elapsed_ms, "timeout", None, "")
    else:
        verdict, notify_type, notes = classify(resp, case.pkt[:8])
        result = FuzzResult(case, resp, elapsed_ms, verdict, notify_type, notes)

    if verbose and resp is not None:
        print(_hex_dump(resp, indent=6))

    return result


# ---------------------------------------------------------------------------
# Main fuzzing loop
# ---------------------------------------------------------------------------

STRATEGIES = ("header", "sa", "ke", "nonce", "payload", "truncate", "random")

VERDICT_COLOR = {
    "accepted":    "\033[32m",  # green
    "rejected":    "\033[36m",  # cyan
    "timeout":     "\033[90m",  # dark grey
    "interesting": "\033[33m",  # yellow
    "malformed":   "\033[31m",  # red
}
RESET = "\033[0m"


def run_fuzzer(
    cfg:         IKEConfig,
    host:        str,
    port:        int,
    strategies:  list[str],
    rounds:      int,
    seed:        int,
    delay:       float,
    timeout:     float,
    report_path: Optional[str],
    verbose:     bool,
    color:       bool,
) -> list[FuzzResult]:
    """
    Build fuzz cases from the selected strategies, send each to the responder,
    classify the response, and return all FuzzResult objects.

    Writes a JSON report to `report_path` if provided.
    """
    use_color = color and sys.stdout.isatty()

    def _cprint(text: str, verdict: str) -> str:
        """Apply ANSI colour to `text` based on verdict; no-op when colour is disabled."""
        if not use_color:
            return text
        return VERDICT_COLOR.get(verdict, "") + text + RESET

    # Build the base packet once; mutations derive from it
    print(f"\nBuilding base IKE_SA_INIT packet  ({cfg.encr}, DH-{cfg.dh_group}) …")
    base_pkt, client = build_base_packet(cfg)
    print(f"  Base packet: {len(base_pkt)} bytes  SPIi={base_pkt[:8].hex()}")

    # Collect fuzz cases
    all_cases: list[FuzzCase] = []
    if "header"   in strategies: all_cases += gen_header_mutations(base_pkt)
    if "sa"       in strategies: all_cases += gen_sa_mutations(base_pkt, cfg)
    if "ke"       in strategies: all_cases += gen_ke_mutations(base_pkt, cfg)
    if "nonce"    in strategies: all_cases += gen_nonce_mutations(base_pkt, cfg)
    if "payload"  in strategies: all_cases += gen_payload_chain_mutations(base_pkt)
    if "truncate" in strategies: all_cases += gen_truncation_cases(base_pkt)
    if rounds > 0:               all_cases += gen_random_mutations(base_pkt, rounds, seed)

    # Assign sequence numbers
    for i, c in enumerate(all_cases, 1):
        c.seq = i
    total = len(all_cases)

    print(f"  Strategies   : {', '.join(strategies)}"
          + (f" + random×{rounds}" if rounds else ""))
    print(f"  Total cases  : {total}")
    print(f"  Target       : {host}:{port}  timeout={timeout}s\n")
    print(f"  {'#':>4}  {'Category':<10}  {'Name':<30}  {'Verdict':<14}  Notes")
    print(f"  {'─'*4}  {'─'*10}  {'─'*30}  {'─'*14}  {'─'*30}")

    results: list[FuzzResult] = []
    for case in all_cases:
        r = send_case(case, host, port, timeout, verbose)
        results.append(r)

        # Format verdict string
        v_str = r.verdict.upper()
        if r.notify_type is not None:
            nname = KNOWN_NOTIFY.get(r.notify_type, str(r.notify_type))
            v_str += f" ({nname})"

        flag = "*** " if r.interesting else "    "
        line = (
            f"  {flag}{case.seq:>3}  {case.category:<10}  "
            f"{case.name:<30}  {r.verdict.upper():<14}  {r.notes}"
        )
        print(_cprint(line, r.verdict))
        if case.category == "random" and case.mutations:
            for m in case.mutations:
                print(f"              [{m['offset']:3d} {m['field']}]"
                      f"  {m['original']} → {m['modified']}")

        if delay > 0:
            time.sleep(delay)

    # Summary
    tally: dict[str, int] = {}
    for r in results:
        tally[r.verdict] = tally.get(r.verdict, 0) + 1
    interesting = [r for r in results if r.interesting]

    bar = "─" * 60
    print(f"\n{bar}")
    print("  Fuzzing summary")
    print(bar)
    print(f"  Cases sent   : {total}")
    for v in ("accepted", "rejected", "timeout", "interesting", "malformed"):
        if tally.get(v, 0):
            line = f"  {v.capitalize():<14}: {tally[v]}"
            print(_cprint(line, v))

    if interesting:
        print(f"\n  *** {len(interesting)} INTERESTING finding(s):")
        for r in interesting:
            print(f"    [{r.case.seq:>3}] {r.case.name:<32}  expected={r.case.expected}  got={r.verdict}")
            print(f"          {r.case.description}")
            if r.notes:
                print(f"          {r.notes}")
    else:
        print("\n  No unexpected findings.")
    print(bar)

    # JSON report
    if report_path:
        report = {
            "target":    f"{host}:{port}",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "config":    {"encr": cfg.encr, "prf": cfg.prf,
                          "integ": cfg.integ, "dh_group": cfg.dh_group,
                          "psk": "***"},
            "strategies": strategies,
            "rounds":    rounds,
            "seed":      seed,
            "summary":   dict(total=total, **tally,
                              interesting_findings=len(interesting)),
            "findings":  [r.to_dict() for r in interesting],
            "all":       [r.to_dict() for r in results],
        }
        with open(report_path, "w") as fh:
            json.dump(report, fh, indent=2)
        print(f"\n  Report saved → {report_path}")

    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Build and return the CLI argument parser for ike_fuzzer.py."""
    p = argparse.ArgumentParser(
        prog="ike_fuzzer.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            IKEv2 protocol fuzzer — mutates IKE_SA_INIT packets and probes a responder.

            Strategies:
              header   — IKE fixed header fields (exchange type, flags, length, SPIs, …)
              sa       — SA payload transforms and proposal structure
              ke       — KE payload DH group and public key
              nonce    — Nonce payload length and content
              payload  — Payload-chain next_payload pointers and unknown payloads
              truncate — Send packet truncated at various offsets
              random   — Random byte flips (count set by --rounds)

            Examples:
              %(prog)s 10.0.0.1
              %(prog)s 10.0.0.1 --strategy header,sa,ke --rounds 0
              %(prog)s 10.0.0.1 --rounds 100 --seed 42 --report out.json
        """),
    )
    p.add_argument("host", help="Responder IP address or hostname")
    p.add_argument("-p", "--port",     type=int,   default=500)
    p.add_argument("--encr",          default="aes-cbc-256",
                   choices=["aes-cbc-128","aes-cbc-256","aes-gcm-128","aes-gcm-256","3des"])
    p.add_argument("--prf",           default="hmac-sha256",
                   choices=["hmac-sha1","hmac-sha256","hmac-sha384","hmac-sha512"])
    p.add_argument("--integ",         default="hmac-sha256-128",
                   choices=["hmac-md5-96","hmac-sha1-96","hmac-sha256-128",
                             "hmac-sha384-192","hmac-sha512-256"])
    p.add_argument("--dh-group",      type=int,   default=14,
                   choices=[2, 5, 14, 19, 20, 21])
    p.add_argument("--psk",           default="secret")
    p.add_argument("--strategy",      default=",".join(STRATEGIES),
                   help="Comma-separated strategy list (default: all)")
    p.add_argument("--rounds",        type=int,   default=20,
                   help="Number of random-mutation cases (0 = skip random, default: 20)")
    p.add_argument("--seed",          type=int,   default=1337,
                   help="RNG seed for random mutations (default: 1337)")
    p.add_argument("--delay",         type=float, default=0.05,
                   help="Seconds between sends (default: 0.05)")
    p.add_argument("--timeout",       type=float, default=2.0,
                   help="UDP response timeout per case (default: 2.0)")
    p.add_argument("--report",        metavar="FILE",
                   help="Save JSON report to FILE")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Hex-dump each response")
    p.add_argument("--no-color",      action="store_true",
                   help="Disable ANSI colour output")
    return p


def main() -> None:
    """Parse CLI arguments and invoke run_fuzzer with the requested configuration."""
    parser = build_parser()
    args   = parser.parse_args()

    strategies = [s.strip() for s in args.strategy.split(",") if s.strip()]
    unknown = [s for s in strategies if s not in STRATEGIES]
    if unknown:
        parser.error(f"Unknown strategy/strategies: {', '.join(unknown)}. "
                     f"Valid: {', '.join(STRATEGIES)}")

    cfg = IKEConfig(
        host      = args.host,
        port      = args.port,
        encr      = args.encr,
        integ     = args.integ,
        prf       = args.prf,
        dh_group  = args.dh_group,
        psk       = args.psk,
        verbose   = args.verbose,
    )

    run_fuzzer(
        cfg         = cfg,
        host        = args.host,
        port        = args.port,
        strategies  = strategies,
        rounds      = args.rounds,
        seed        = args.seed,
        delay       = args.delay,
        timeout     = args.timeout,
        report_path = args.report,
        verbose     = args.verbose,
        color       = not args.no_color,
    )


if __name__ == "__main__":
    main()
