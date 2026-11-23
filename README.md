# Secret Leak Scanner

**English** | [简体中文](README.zh-CN.md)

A small Python CLI that finds **API keys, tokens, passwords and private keys that were
accidentally committed** to a code repository. It combines two techniques:

1. **Regex rules** for secrets with a known format (AWS, GitHub, GitLab, Slack, Stripe,
   Google, OpenAI, Anthropic, JWTs, private key headers, `user:password@` in URLs).
2. **Shannon entropy** for secrets that have no fixed format: values assigned to names
   like `password` / `api_key` / `token`, and long random-looking strings.

It can scan a directory, only the lines you're about to commit (as a **git pre-commit
hook**), or the whole git history.

Standard library only: no `pip install`. Python 3.8+ and git.

## Usage

```bash
python3 secret_scan.py scan .                 # scan the working tree
python3 secret_scan.py scan src config.yml    # specific dirs/files
python3 secret_scan.py scan . --json          # machine-readable (secrets still masked)
python3 secret_scan.py staged                 # only the added lines in `git add`ed changes
python3 secret_scan.py history                # every line ever added in git history
python3 secret_scan.py history --all --max-count 500

python3 secret_scan.py install-hook           # run `staged` before every commit

python3 -m unittest -v                        # offline tests
```

Example output (the CLI prints in Chinese; all values in this demo are random):

```
[!] .env:1  secret-assignment  L8dK…(28 字符)  fp:0e98dcc7ddce3a3a
    疑似硬编码秘密（STRIPE_TOKEN）
[!] app/client.js:1  high-entropy-string  xgJT…(40 字符)  fp:1ed3f93b37356efe
    高熵字符串 (熵 4.92)
[!] app/settings.py:2  aws-access-key-id  AKIA…(20 字符)  fp:c29a443c4d869a29
    AWS Access Key ID
[!] app/settings.py:3  url-credentials  pfJB…(12 字符)  fp:c819b71a24f270f1
    URL 里的明文密码 (scheme://user:pass@host)
⚠️  发现 4 处疑似密钥泄露。
```

(`疑似硬编码秘密` = looks like a hard-coded secret, `高熵字符串` = high-entropy string,
`字符` = characters, `发现 4 处疑似密钥泄露` = 4 possible leaks found.)

**Secrets are always masked** (first 4 characters + length), so the scanner's own output
doesn't leak them again into a terminal log or CI job. `--show-secrets` turns this off.

| Exit code | Meaning |
|---|---|
| `0` | Nothing found |
| `1` | Possible secrets found (the pre-commit hook blocks the commit) |
| `2` | Error (path missing, not a git repo…) |

## How it works

```
 files / staged diff / git log -p
               │
               ▼
 ┌─ 1. format rules ─────────┐   AKIA…, ghp_…, xoxb-…, sk_live_…, AIza…,
 │   high confidence         │   BEGIN … PRIVATE KEY, eyJ….eyJ….…, ://user:pass@
 └───────────┬───────────────┘
             ▼  (spans already matched are skipped below → no double reports)
 ┌─ 2. sensitive name = value ┐   password = "…", "api_key": "…", TOKEN=… (.env/yaml/ini)
 │   keep if entropy ≥ 3.0    │   drops placeholders, env lookups, plain words
 └───────────┬───────────────┘
             ▼
 ┌─ 3. any quoted string ────┐   ≥ 20 chars of [A-Za-z0-9+/=_-], upper+lower+digit,
 │   keep if entropy ≥ 4.5   │   ≤ 200 chars
 └───────────┬───────────────┘
             ▼
   allowlist (inline comment, .secretsignore)  →  masked report + exit code
```

### Shannon entropy

For a string *s*, H(s) = −Σ p(c) · log₂ p(c), summed over each distinct character *c*,
where p(c) is how often *c* appears. It measures "bits of surprise per character":

| String | H (bits/char) |
|---|---|
| `aaaaaaaa` | 0 |
| `hello_world_this_is_text` | ≈ 3.4 |
| a 40-character random base64 key | ≈ 4.9–5.3 |

Machine-generated keys are random, so they score high; words and identifiers score low.
The maximum for a string of length *n* is log₂ *n*, which is why the entropy rule
also requires a minimum length: a short string can't reach a high score.

### Cutting down false positives
Entropy alone is very noisy, so each layer has filters, tuned by scanning a large
`site-packages` tree:
- **Placeholders are skipped**: `${DB_PASS}`, `<YOUR_API_KEY>`, `changeme`, `example`,
  `xxxx`, `os.environ[...]`, `process.env...`, f-string fields `{var}`.
- **Names that describe a secret but aren't one** are skipped: `token_type`,
  `auth_method`, `password_field`, `api_key_header`…
- Values with spaces (sentences), pure-letter identifiers (`privateKeyUsagePeriod`),
  alphabet constants (`ABCDEFGH…0123…`), lowercase hex (git SHAs, checksums), and strings
  over 200 characters (embedded images and certificates) are not reported by the entropy
  rules.
- Unquoted `KEY=value` is only checked in config files (`.env*`, `.ini`, `.yaml`,
  `.toml`, `.properties`…), where `password = get_password()` can't appear.
- Skipped automatically: `.git`, `node_modules`, virtualenvs, build output, binary files
  (NUL byte in the first 8 KiB), files over 1 MiB (`--max-size`), and lock files
  (`package-lock.json`, `poetry.lock`, `go.sum`…, which are full of integrity hashes).

### Speed
Each regex runs **once over the whole file** instead of once per line, so the loop
stays inside Python's C regex engine; match offsets are mapped back to line numbers
with a binary search. Every rule pattern starts with a literal (`AKIA`, `ghp_`, `://`…)
so the engine can jump straight to candidates. For sensitive names the text is
lower-cased once instead of using a slower case-insensitive regex. Result: about
7,600 files and 2.6 million lines in ~5 seconds.

## Allowlist (marking false positives)

1. **Inline**: put `secret-scan: allow` in a comment on the same line.
   ```python
   TEST_KEY = "…fake value…"  # secret-scan: allow
   ```
2. **`.secretsignore`** in the scanned root / repo root (or `--ignore-file`):
   ```
   # path globs: skip whole files or directories
   tests/fixtures/
   *.snap
   # a single finding, by the fingerprint printed in the report
   fp:1ed3f93b37356efe
   ```

The fingerprint is `sha256(rule + ":" + secret)` truncated to 16 hex characters. It
identifies that exact value without writing the value itself into the repo. It doesn't
depend on the file path or line number, so it keeps working when code moves around.

## Pre-commit hook

```bash
cd your-repo
python3 /path/to/secret_scan.py install-hook
```

This writes `.git/hooks/pre-commit` (it respects `core.hooksPath`) which runs
`secret_scan.py staged`. It refuses to overwrite a hook it didn't write unless you pass
`--force`.

`staged` parses `git diff --cached -U0` and only scans **added lines**, so an old
finding you've already dealt with won't block every future commit, and the reported
line numbers are the line numbers in the new file.

## If you find a real leak

Deleting the line and committing again is **not enough**: the secret is still in git
history (that's exactly what `history` finds), in every clone and fork, and possibly in
CI logs. In order:

1. **Revoke / rotate the key at the provider first.** Assume it's already been copied;
   bots scrape public GitHub pushes within minutes.
2. Then remove it from the code and load it from an environment variable or a secret
   manager.
3. Optionally rewrite history (`git filter-repo`, BFG) and force-push. This keeps the
   secret out of future clones, but it doesn't make a rotated key safe again or remove
   copies others already have.

## Limitations
- **Heuristics, not proof.** Expect some false positives (the allowlist exists for that)
  and false negatives: a weak, low-entropy password like `summer2024`, a secret split
  across string concatenation, or one that is base64-, hex- or otherwise encoded will be
  missed.
- **No verification.** It doesn't call provider APIs to check whether a key is live.
  Tools like TruffleHog do that, but it means sending the secret to the network.
- Rules cover common providers only. Add your own by appending to `RULES`.
- Private keys are detected by their `BEGIN … PRIVATE KEY` header line only.
- Hex strings aren't entropy-checked (too many hashes in real code), so a hex-only API
  token is only caught when it's assigned to a sensitive name.
- `git commit --no-verify` skips client-side hooks. For enforcement, also run `scan` or
  `history` in CI, and turn on GitHub's push protection.
- `history` reads the whole `git log -p` output into memory; very large repositories
  should use `--max-count`.

## Files
- `secret_scan.py`: the CLI (rules → entropy → allowlist → targets → report → hook)
- `test_secret_scan.py`: offline tests (rules, entropy filters, allowlist, masking, a
  temp git repo for staged/history/hook, and a check that the scanner's own repo is
  clean). **All fake secrets are generated at runtime**, so the source contains nothing
  that looks like a real key and pushing it doesn't trip GitHub push protection.

## References
- Shannon, "A Mathematical Theory of Communication" (1948)
- OWASP Secrets Management Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
- GitHub secret scanning:
  https://docs.github.com/en/code-security/secret-scanning
- Similar tools: [gitleaks](https://github.com/gitleaks/gitleaks),
  [TruffleHog](https://github.com/trufflesecurity/trufflehog),
  [detect-secrets](https://github.com/Yelp/detect-secrets)
