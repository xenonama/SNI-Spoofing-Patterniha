# SECURITY.md — Threat Model, Privacy, and Compliance

## 1. What this tool does

SNI Spoofing Tool injects decoy TLS ClientHellos (fake SNI, wrong sequence
numbers) via WinDivert on Windows so on-path DPI that filters by cleartext
SNI sees a benign hostname while the real handshake still reaches the
configured endpoint. Optional Trojan + Xray mode proxies traffic (SOCKS5 /
HTTP) and passes QUIC/HTTP-3 through untouched.

What it is **not**: a VPN, Tor, or malware. It does not exploit servers,
does not strip TLS, and does not decrypt anyone else's traffic.

## 2. Threat model

**Protects against:**

- Passive SNI-based filtering / logging on the local network or ISP
  (cleartext `server_name` in TLS ClientHello, QUIC Initial SNI).
- Naive DPI that matches the first SNI string or JA3 without full
  reassembly (countered by `hostfakesplit`, `fakedsplit`, fragmented
  overlap, fingerprint profiles mimicking Chrome/Firefox).

**Does NOT protect against:**

- Endpoint compromise, malicious exit nodes, or the destination server
  itself logging your IP.
- Active MITM with a trusted root CA installed on your machine, traffic
  correlation / timing analysis, or full TLS interception.
- Encrypted ClientHello (ECH) enforcement points that block unknown ECH
  stubs, or DPI that does full TCP reassembly with correct sequence
  handling (fake segments use old sequence numbers precisely so the real
  server ignores them — a reassembling DPI may still see through them).
- DNS surveillance (use DoH/DoT separately), or QUIC fingerprinting when
  QUIC is set to `passthrough`.

**Assumptions:**

- Windows + Administrator + intact WinDivert driver (`pydivert`).
- The configured endpoints (`config.json` ENDPOINTS) are trusted.
- The local `config.json` / `config.json.full.json` / `xray_config.json`
  are not tampered with (see §4).

## 3. How privacy is protected in this codebase

- **Minimal logging:** backend defaults to `WARNING+`; per-packet info is
  never written. `utils/security.py::sanitize_log_msg` redacts IPv4 and
  known SNIs; `SanitizingFilter` applies it to every record; logs rotate
  (2 MB × 3) and auto-delete after 7 days.
- **No SNI/endpoint in stdout:** startup prints counts + one-way hashes
  (`hash_sni`), never raw domains/IPs. GUI console hides routine
  per-packet lines (`_is_routine_injector_line`).
- **Config hardening:** `secure_load_json` enforces size caps (256 KB),
  UTF-8 JSON only (no eval/exec/pickle), and an allowlist
  (`ALLOWED_CONFIG_KEYS`); every network field is re-validated
  (`is_valid_ipv4`, `validate_port`, `is_valid_sni`) plus a last-mile
  `sanitize_for_socket` check before `connect`/`bind`.
- **DoS guards:** `BoundedExecutor` (16 workers, 64 queued, 10 s task
  timeout) + `MAX_CONNECTIONS` semaphore + `connection_reaper` prevent
  memory growth from stalled endpoints.
- **Secure shutdown:** `secure_cleanup` / `_secure_shutdown` overwrite and
  clear SNI/endpoint dicts, shred temp files, and run on `atexit`, SIGINT,
  and SIGTERM.
- **Path safety:** profile save/load and config paths go through
  `validate_file_path` (anti-traversal, no reserved device names) and
  atomic writes (`atomic_write_json` + `os.replace`).

## 4. Residual risks and safe use

- Running as Administrator + loading a kernel driver (WinDivert) is
  inherently privileged. Only run builds you compiled yourself or got
  from a trusted source; verify `sc qc WinDivert` shows `DEMAND_START`
  (not DISABLED) and matching 64/32-bit Python.
- A swapped `config.json` can redirect traffic: keep the app directory
  writable only by Administrators, and review `ENDPOINTS` / `FAKE_SNIS`
  before pressing START.
- Fingerprint profiles are approximations. Refresh quarterly with
  `python refresh_profiles.py --guide` / `--check`; rotate profiles when
  one stops working rather than disabling TLS verification elsewhere.
- Xray/Trojan mode adds real proxy credentials (`TROJAN_PASSWORD`):
  use a strong unique password, keep `xray_config.json` private, and do
  not share `config.json.full.json` publicly (it contains your endpoints).

## 5. Legal / network-policy compliance ⚠️

- **You are responsible for complying with local law and your network's
  acceptable-use policy.** Bypassing censorship, workplace, school, or
  carrier filtering may violate statutes, contracts, or terms of service
  and can lead to account termination, disciplinary action, or prosecution.
- Do not use this tool to access content you have no right to access, to
  impersonate others, to attack networks, or to evade lawful interception.
- If in doubt, seek legal advice **before** running the injector, and
  prefer explicit, permitted connectivity (VPN approved by your org, Tor
  where lawful, direct access) over evasion.

## 6. Reporting vulnerabilities

Do not open public issues with sensitive details (endpoints, SNIs, logs).
Redact with `sanitize_log_msg`, describe reproduction with
`python main.py --self-test` output, and state the Windows / Python /
pydivert versions. See `credit.txt` for upstream contacts.
