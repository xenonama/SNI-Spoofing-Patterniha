"""Refresh TLS fingerprint profiles from real browser captures.

Stdlib only, Windows-safe, offline-safe. Two modes:

  python refresh_profiles.py --check
      Validate current profiles in utils/tls_fingerprint.py:
      JA3 present, ClientHello length sane, ALPS (0x001C) + ECH (0xFE0D)
      present on modern profiles, GREASE well-formed.

  python refresh_profiles.py --guide
      Print the step-by-step refresh procedure (curl-impersonate,
      Wireshark, JA3 databases) and the exact constants to update.

Why this exists: DPI boxes key on JA3 (cipher order, extension order,
GREASE, ALPS/ECH). Browsers rotate GREASE seeds and add extensions
every few releases; a stale hardcoded profile stands out. Re-capture
quarterly (or when a profile stops working) and update
utils/tls_fingerprint.py::_PROFILE_DEFS + _CIPHER_CORE_* + HTTP2_SETTINGS_DEFS.

No network calls are made by this script (offline-safe by design).
"""
from __future__ import annotations

import argparse
import sys

GUIDE = r"""
TLS FINGERPRINT REFRESH GUIDE
=============================
Goal: update utils/tls_fingerprint.py so fake ClientHellos still blend in.

1) Capture a fresh ClientHello (pick ONE):
   A. curl-impersonate (easiest, no GUI):
       curl-impersonate-chrome124 https://example.com -v --tlsv1.3
       # log the JA3 with: --ja3 works in some builds; otherwise capture below.
   B. Wireshark (ground truth):
       1. Close browser, start capture on your interface, filter: tls.handshake.type == 1
       2. Open the target browser version, visit https://example.com once.
       3. Stop capture, select the ClientHello -> expand:
          Cipher Suites, Extension list (in order), Supported Groups,
          Signature Schemes, ALPN, key_share groups, GREASE values (0x?A?A),
          padding length, session_id length.
   C. Public JA3 databases (cross-check only, never copy blindly):
       https://ja3er.com/search , https://sslbl.abuse.ch/ja3-fingerprints/
       Search "Chrome 12x" / "Firefox 12x", compare cipher + extension order
       against your capture. If they disagree, trust YOUR capture.

2) Translate the capture into code constants:
   - utils/tls_fingerprint.py::_CIPHER_CORE / _CIPHER_CORE_CHROME_124 / _CIPHER_CORE_FF124
     Order matters! Keep TLS 1.3 suites (0x1301..) first, then ECDHE, then CBC.
   - _PROFILE_DEFS[<browser>]["curves"]  (supported_groups, GREASE first for Chrome)
   - _PROFILE_DEFS[<browser>]["versions"] (supported_versions, GREASE first for Chrome)
   - _PROFILE_DEFS[<browser>]["ext_order"] (exact wire order incl. "alps","ech","padding")
   - _PROFILE_DEFS[<browser>]["ciphers"][0] = fresh GREASE seed
     (rotate among 0x0A0A..0xFAFA where (v & 0x0F0F)==0x0A0A; never reuse the
     same seed across chrome_120/chrome_124/custom at the same time).
   - _PROFILE_DEFS[<browser>]["pad_to"] (Chrome pads record to 512B via ext 21)
   - HTTP2_SETTINGS_DEFS (only if the browser changed its SETTINGS table;
     check akamai h2 datasets or curl-impersonate source tables).

3) Verify locally (must all pass before committing):
     python main.py --self-test
     python refresh_profiles.py --check
     pytest -q
   Check in particular:
     - TlsFingerprintGenerator.ja3(profile) matches your capture's JA3
       (GREASE removed, compare with ja3er output).
     - find_client_hello_extensions(hello) contains ALPS_EXT_TYPE (0x001C)
       and ECH_EXT_TYPE (0xFE0D) for chrome_124/firefox_124/chrome_120/firefox_122/custom.
     - len(get_client_hello(b"example.com", "chrome_*")) == 512 (padded),
       firefox_* ~316B, legacy == 517B.
     - Wireshark parses the generated hello without "Malformed Packet".

4) Roll out safely:
   - Keep the old profile for one release (rename to custom) so users can
     rotate back if the new one is blocked ("rotate when others burn").
   - Note the browser version + capture date in the _PROFILE_DEFS comment.
   - Never commit real user SNIs or keys; test SNI is always example.com.

Frequency: quarterly, or when success_rate drops on a profile that used to work.
"""


def check_profiles() -> int:
    try:
        from utils.tls_fingerprint import (
            TlsFingerprintGenerator as G,
            find_client_hello_extensions,
            ALPS_EXT_TYPE,
            ECH_EXT_TYPE,
            _is_grease,
        )
    except Exception as exc:
        print("FAIL: cannot import tls_fingerprint: %s" % exc)
        return 1
    ok = True
    modern = ("chrome_120", "chrome_124", "firefox_122", "firefox_124", "custom")
    print("profile            len  ja3_md5                           ALPS ECH GREASE")
    for prof in ("legacy",) + modern:
        try:
            hello = G.get_client_hello(b"example.com", prof)
            exts = find_client_hello_extensions(hello)
            ja3h = G.ja3_hash(prof)
            ja3s = G.ja3(prof)
            assert hello[:3] == b"\x16\x03\x01" and hello[5] == 0x01, "bad record/hello header"
            assert "-" in ja3s and len(ja3h) == 32, "bad JA3"
            if prof == "legacy":
                assert len(hello) == 517, f"legacy must stay 517B, got {len(hello)}"
                alps = ech = "-"
            else:
                alps = "Y" if ALPS_EXT_TYPE in exts else "N"
                ech = "Y" if ECH_EXT_TYPE in exts else "N"
                if alps != "Y" or ech != "Y":
                    print(f"FAIL: {prof}: ALPS/ECH missing: {exts}")
                    ok = False
                if prof.startswith("chrome") or prof == "custom":
                    assert len(hello) == 512, f"{prof} must pad to 512B, got {len(hello)}"
            # GREASE sanity on Chrome-like profiles.
            grease = "-"
            if prof in ("chrome_120", "chrome_124", "custom"):
                try:
                    from utils.tls_fingerprint import PROFILE_DEFS
                    seed = PROFILE_DEFS[prof]["ciphers"][0]
                    grease = "Y" if _is_grease(seed) else "N(%04X)" % seed
                    if grease != "Y":
                        print(f"WARN: {prof}: first cipher not GREASE: {seed:#06x}")
                except Exception:
                    pass
            print(f"{prof:18s} {len(hello):4d}  {ja3h}  {alps:>4s} {ech:>3s} {grease:>6s}")
        except Exception as exc:
            print(f"FAIL: {prof}: {exc}")
            ok = False
    # Determinism: same (sni, profile) must give identical bytes (cache path).
    try:
        a = G.get_client_hello(b"example.com", "chrome_120")
        b = G.get_client_hello(b"example.com", "chrome_120")
        assert a == b, "template cache non-deterministic"
    except Exception as exc:
        print(f"FAIL: determinism: {exc}")
        ok = False
    print("CHECK %s" % ("OK" if ok else "FAILED"))
    return 0 if ok else 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="TLS profile refresh helper")
    p.add_argument("--check", action="store_true", help="validate current profiles")
    p.add_argument("--guide", action="store_true", help="print refresh guide")
    args = p.parse_args(argv)
    if args.guide or not args.check:
        print(GUIDE.strip())
        print()
    if args.check or not args.guide:
        if not args.check and not args.guide:
            # No flags: print guide + run check (most useful default).
            return check_profiles()
        if args.check:
            return check_profiles()
    return 0


if __name__ == "__main__":
    sys.exit(main())
