# strongSwan test container

Runs a strongSwan 5.9 responder on `127.0.0.1:500` (host network) with
pre-shared-key authentication for testing the IKE client.

## Build & run

```bash
cd docker/strongswan
docker build -t ike-test-swan .
docker run --rm --network host --name swan-test ike-test-swan
```

## Connections

| Name | Version | Mode | Proposals |
|---|---|---|---|
| `ikev1-main` | IKEv1 | Main Mode | AES-256-CBC + SHA-1/256/512 + MODP-2048, AES-256-CBC + SHA-256 + ECP-521 |
| `ikev1-agg` | IKEv1 | Aggressive Mode | AES-256-CBC + SHA-1/256/512 + MODP-2048, AES-256-CBC + SHA-256 + ECP-521 |
| `ikev2-psk` | IKEv2 | — | AES-256-CBC + SHA-256/1 + MODP-2048, AES-256-GCM-16 + MODP-2048 |
| `ikev2-psk-gcm` | IKEv2 | — | AES-256-GCM-16 + PRF-SHA-256 + MODP-2048 |
| `ikev2-gcm-sha512` | IKEv2 | — | AES-256-GCM-16 + PRF-SHA-512 + ECP-521 |

PSK: `secret`

## Sample client commands

```bash
# IKEv1 Main Mode, MODP-2048
python ike_client.py 127.0.0.1 --version 1 --mode main --psk secret --encr aes-cbc-256 --hash sha256 --dh-group 14

# IKEv1 Main Mode, ECP-521
python ike_client.py 127.0.0.1 --version 1 --mode main --psk secret --encr aes-cbc-256 --hash sha256 --dh-group 21

# IKEv1 Aggressive Mode, MODP-2048
python ike_client.py 127.0.0.1 --version 1 --mode aggressive --psk secret --encr aes-cbc-256 --hash sha256 --dh-group 14

# IKEv2 AES-CBC-256 / SHA-256 / MODP-2048
python ike_client.py 127.0.0.1 --version 2 --encr aes-cbc-256 --integ hmac-sha256 --prf hmac-sha256 --dh-group 14 --psk secret

# IKEv2 AES-GCM-256 / PRF-SHA-256 / MODP-2048
python ike_client.py 127.0.0.1 --version 2 --encr aes-gcm-256 --prf hmac-sha256 --dh-group 14 --psk secret

# IKEv2 AES-GCM-256 / PRF-SHA-512 / ECP-521
python ike_client.py 127.0.0.1 --version 2 --encr aes-gcm-256 --prf hmac-sha512 --dh-group 21 --psk secret
```

## Notes

- `interfaces_use = lo` restricts charon to the loopback interface.
- `i_dont_care_about_security_and_use_aggressive_mode_psk = yes` is required by
  strongSwan ≥ 5.4 to permit Aggressive Mode with PSK (disabled by default due
  to offline dictionary attack exposure).
- `libstrongswan-standard-plugins` and `libstrongswan-extra-plugins` provide the
  `gcm` and `openssl` plugins needed for AES-GCM and elliptic-curve DH support.
