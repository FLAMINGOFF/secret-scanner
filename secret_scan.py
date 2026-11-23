#!/usr/bin/env python3
"""
密钥泄露扫描器 (Secret Leak Scanner)

在代码仓库里找「不小心提交的」API key、token、密码、私钥。两种检测方式叠加：
  1. 正则规则：已知格式的密钥（AWS、GitHub、Slack、Stripe、Google、私钥头……），准确率高
  2. 香农熵：  对「password = "..."」这类赋值和长随机字符串算信息熵，
              熵越高越像随机生成的密钥，用来抓没有固定格式的秘密

三种扫描目标：
  scan PATH...    扫描目录/文件（工作区）
  staged          只扫描 git 暂存区里「新增的行」—— 给 pre-commit hook 用
  history         扫描 git 历史里所有提交新增过的行（删掉的密钥仍在历史里！）

另有 install-hook 子命令，把 staged 扫描装成 .git/hooks/pre-commit。

误报处理（allowlist）：
  - 行内注释 `secret-scan: allow` 跳过这一行
  - 仓库根目录的 .secretsignore：每行一个路径 glob，或 `fp:<指纹>` 忽略某个具体发现

只依赖 Python 标准库，Python 3.8+ 可直接运行。输出里的密钥一律打码，不会原样打印。
"""

import argparse
import bisect
import fnmatch
import hashlib
import json
import math
import os
import re
import subprocess
import sys
from collections import Counter

# 退出码
EXIT_CLEAN, EXIT_FOUND, EXIT_ERROR = 0, 1, 2

MAX_FILE_SIZE = 1024 * 1024           # 默认跳过大于 1 MiB 的文件
IGNORE_FILE = ".secretsignore"
INLINE_ALLOW = "secret-scan: allow"

# 默认不进入的目录
SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
             ".tox", ".mypy_cache", ".pytest_cache", "dist", "build", ".idea"}
# 锁文件里全是 integrity 哈希，熵很高但不是秘密
SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
              "Pipfile.lock", "Cargo.lock", "go.sum", "composer.lock", "Gemfile.lock",
              IGNORE_FILE}
# 这些扩展名的文件里，允许不带引号的赋值（KEY=value）
CONFIG_EXTS = {".env", ".ini", ".cfg", ".conf", ".properties", ".yaml", ".yml", ".toml"}

# ───────────────────────── 第 1 步：规则 ─────────────────────────
# (规则名, 说明, 正则)。正则若有捕获组，第 1 组就是「秘密本体」，否则用整个匹配。

RULES = [
    ("private-key", "私钥文件头",
     re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")),
    ("aws-access-key-id", "AWS Access Key ID",
     re.compile(r"(A[KS]IA[0-9A-Z]{16})\b")),
    ("aws-secret-access-key", "AWS Secret Access Key",
     re.compile(r"(?i:aws.{0,20}?secret.{0,20}?)[\"' \t:=]+([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])")),
    ("github-token", "GitHub token",
     re.compile(r"(gh[pousr]_[A-Za-z0-9]{36,255})\b")),
    ("github-fine-grained-pat", "GitHub fine-grained token",
     re.compile(r"(github_pat_[A-Za-z0-9_]{60,255})\b")),
    ("gitlab-token", "GitLab personal access token",
     re.compile(r"(glpat-[A-Za-z0-9_-]{20,})")),
    ("slack-token", "Slack token",
     re.compile(r"(xox[abposr]-[A-Za-z0-9-]{10,})")),
    ("slack-webhook", "Slack incoming webhook",
     re.compile(r"(https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+)")),
    ("stripe-secret-key", "Stripe live secret key",
     re.compile(r"([sr]k_live_[A-Za-z0-9]{20,})")),
    ("google-api-key", "Google API key",
     re.compile(r"(AIza[0-9A-Za-z_-]{35})(?![0-9A-Za-z_-])")),
    ("anthropic-api-key", "Anthropic API key",
     re.compile(r"(sk-ant-[A-Za-z0-9_-]{40,})")),
    ("openai-api-key", "OpenAI API key",
     re.compile(r"(sk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_-]{40,})")),
    ("jwt", "JSON Web Token",
     re.compile(r"(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})")),
    ("url-credentials", "URL 里的明文密码 (scheme://user:pass@host)",
     re.compile(r"://[^\s:/@\"']+:([^\s:/@\"']{3,})@[^\s\"']+")),
]

# 规则正则都以字面量开头（没有前置 \b），这样 re 能用快速的前缀查找；
# 「前面不能紧挨着字母数字」这个边界在代码里检查（见 scan_lines）。

# 变量名里出现这些词，就把它的值当成可能的秘密（只匹配小写：在 text.lower() 上跑，比 (?i) 快很多）
SECRET_NAME = (r"(?:pass(?:word|wd|phrase)|pwd|secret|token|api[_-]?key|apikey"
               r"|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?key|credentials?)")
# password = "xxx" / "api_key": "xxx" / token: 'xxx'（带引号，任何文件）
ASSIGN_QUOTED = re.compile(
    SECRET_NAME + r"[\w.-]*[\"']?[ \t]*(?::=|=>|==|=|:)[ \t]*"
    r"(?:[rbuf]{0,2})([\"'])(.*?)(?<!\\)\1")
# PASSWORD=xxx / password: xxx（不带引号，仅配置文件）
ASSIGN_BARE = re.compile(SECRET_NAME + r"[\w.-]*[ \t]*[:=][ \t]*([^\s\"'#;]+)")
BARE_LINE_PREFIX = re.compile(r"[ \t]*(?:export[ \t]+)?[\w.-]*")   # 键名前面只能有这些
WORD_CHAR = re.compile(r"[\w.-]")
# 任意引号里的长字符串，用于熵检测
QUOTED_STRING = re.compile(r"([\"'`])([A-Za-z0-9+/=_-]{20,})\1")

# 一看就是占位符/引用变量的值：不报
PLACEHOLDER = re.compile(
    r"(?i)^(?:\$|%\(|<|\*{3}|x{4,}|\.{3})|\{[^}]*\}|\$\{|example|sample|changeme|change_me|"
    r"your[_-]|placeholder|dummy|redacted|replace|todo|fixme|^(?:none|null|nil|true|false|"
    r"undefined|password|passwd|pass|pwd|user|username|secret|token|test|testing)$|getenv|environ|process\.env|"
    r"^[a-z_]+\.[a-z_.]+$")

# 变量名以这些结尾，说的是「秘密的元数据」而不是秘密本身（token_type、auth_method……）
KEY_META_SUFFIX = re.compile(
    r"(?i)[_.-](?:type|types|method|hint|pattern|name|names|url|uri|endpoint|file|path|field|"
    r"header|prefix|len|length|size|id|env|var|key_name|regex|re|format|label|enders|chars)$")

PASSWORD_MIN_LEN = 8
PASSWORD_MIN_ENTROPY = 3.0
ENTROPY_MIN_LEN = 20
ENTROPY_MAX_LEN = 200          # 更长的一般是内嵌数据（base64 图片、证书包），不是 API key
ENTROPY_THRESHOLD = 4.5


# ───────────────────────── 第 2 步：熵与单行检测 ─────────────────────────

def shannon_entropy(s: str) -> float:
    """香农熵（比特/字符）：H = -Σ p(c)·log2 p(c)。
    全是同一个字符 → 0；字符越多越均匀 → 越高。随机 base64 约 5~6，英文单词约 2.5~3.5。"""
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def char_classes(s: str) -> int:
    """出现了几类字符（小写/大写/数字）。真正的随机 key 通常三类都有。"""
    return sum(bool(re.search(p, s)) for p in ("[a-z]", "[A-Z]", "[0-9]"))


# 字母表/数字表常量（"ABCDEFGHIJ...0123456789"）熵很高但不是秘密
SEQUENCE = re.compile(r"(?i)abcdefgh|0123456|qwertyui")


def is_placeholder(value: str) -> bool:
    if value != value.strip():        # 首尾有空格：多半是 "KEY=" + var 这种拼接，不是值本身
        return True
    return bool(PLACEHOLDER.search(value)) or len(set(value)) <= 2


def fingerprint(rule: str, secret: str) -> str:
    """发现的指纹：只用于在 .secretsignore 里标记误报，不可逆地代表这个值。"""
    return hashlib.sha256(f"{rule}:{secret}".encode()).hexdigest()[:16]


def mask(secret: str) -> str:
    """打码：只露出前 4 个字符和长度，日志/CI 输出里不会二次泄露。"""
    shown = secret[:4] if len(secret) > 8 else secret[:1]
    return f"{shown}…({len(secret)} 字符)"


def scan_lines(lines, *, config_file=False, use_entropy=True,
               entropy_threshold=ENTROPY_THRESHOLD):
    """检测多行文本，返回 [(行下标, 规则名, 说明, 秘密, 熵)]。

    每个正则对整段文本只跑一次（循环在 C 里，比逐行调用快得多），
    再用二分查找把匹配位置换算回行号。"""
    text = "\n".join(lines)
    starts, pos = [], 0
    for ln in lines:
        starts.append(pos)
        pos += len(ln) + 1
    allowed = {i for i, ln in enumerate(lines) if INLINE_ALLOW in ln}
    found, spans = [], []

    def line_of(offset):
        return bisect.bisect_right(starts, offset) - 1

    def overlaps(a, b):
        return any(a < e and s < b for s, e in spans)

    def add(i, start, end, rule, desc, secret, h):
        spans.append((start, end))
        found.append((start, i, rule, desc, secret, h))

    # 1) 高可信度的格式规则
    for name, desc, rx in RULES:
        g = 1 if rx.groups else 0
        for m in rx.finditer(text):
            i, secret = line_of(m.start(g)), m.group(g)
            st = m.start()
            if st > 0 and text[st].isalnum() and text[st - 1].isalnum():   # 不是词首：xAKIA…、mysk-…
                continue
            if i in allowed or overlaps(m.start(g), m.end(g)):
                continue
            if name in ("url-credentials", "aws-secret-access-key") and is_placeholder(secret):
                continue
            add(i, m.start(g), m.end(g), name, desc, secret, shannon_entropy(secret))

    # 2) 敏感变量名 + 赋值（用熵过滤掉 "password = 'hello'" 这类）
    lower = text.lower()
    if len(lower) != len(text):          # 极少数 Unicode 字符小写后长度会变，逐字符替换保持对齐
        lower = "".join(c.lower() if len(c.lower()) == 1 else c for c in text)

    def key_start(pos):                  # 从关键词往回走，拿到完整变量名（db_password、AWS_SECRET…）
        while pos > 0 and WORD_CHAR.match(text[pos - 1]):
            pos -= 1
        return pos

    def key_of(m):
        k0 = key_start(m.start())
        return k0, text[k0:m.start()] + re.match(r"[\w.-]*", text[m.start():]).group()

    candidates = []
    for m in ASSIGN_QUOTED.finditer(lower):
        _, key = key_of(m)
        candidates.append((key, text[m.start(2):m.end(2)], m.start(2), m.end(2)))
    if config_file:
        for m in ASSIGN_BARE.finditer(lower):
            k0, key = key_of(m)
            line_start = starts[line_of(k0)]
            if BARE_LINE_PREFIX.fullmatch(text[line_start:k0]):
                candidates.append((key, text[m.start(1):m.end(1)], m.start(1), m.end(1)))
    for key, value, s, e in candidates:
        i = line_of(s)
        if (i in allowed or len(value) < PASSWORD_MIN_LEN or is_placeholder(value) or overlaps(s, e)
                or value.lower() == key.lower() or KEY_META_SUFFIX.search(key)
                or re.search(r"\s", value)            # 带空格的多半是句子，不是密码
                or re.fullmatch(r"[A-Za-z_-]+", value)  # 纯字母标识符：privateKeyUsagePeriod
                or char_classes(value) < 2):
            continue
        h = shannon_entropy(value)
        if h >= PASSWORD_MIN_ENTROPY:
            add(i, s, e, "secret-assignment", f"疑似硬编码秘密（{key}）", value, h)

    # 3) 纯熵检测：引号里的长随机串
    if use_entropy:
        for m in QUOTED_STRING.finditer(text):
            value, s, e = m.group(2), m.start(2), m.end(2)
            i = line_of(s)
            if (i in allowed or overlaps(s, e) or is_placeholder(value) or char_classes(value) < 3
                    or len(value) > ENTROPY_MAX_LEN or SEQUENCE.search(value)):
                continue
            h = shannon_entropy(value)
            if h >= entropy_threshold:
                add(i, s, e, "high-entropy-string", f"高熵字符串 (熵 {h:.2f})", value, h)

    return [f[1:] for f in sorted(found, key=lambda f: f[0])]


def scan_line(line: str, **kw):
    """检测单行，返回 [(规则名, 说明, 秘密, 熵)]。"""
    return [f[1:] for f in scan_lines([line], **kw)]


# ───────────────────────── 第 3 步：allowlist ─────────────────────────

class Allowlist:
    """.secretsignore：每行一个路径 glob（如 tests/fixtures/*），或 fp:<指纹>。# 开头是注释。"""

    def __init__(self, globs=(), fingerprints=()):
        self.globs = list(globs)
        self.fingerprints = set(fingerprints)

    @classmethod
    def load(cls, path):
        a = cls()
        if path and os.path.isfile(path):
            with open(path, encoding="utf-8") as f:
                for raw in f:
                    item = raw.split("#", 1)[0].strip()
                    if item.startswith("fp:"):
                        a.fingerprints.add(item[3:].strip())
                    elif item:
                        a.globs.append(item)
        return a

    def path_ignored(self, rel_path: str) -> bool:
        rel_path = rel_path.replace(os.sep, "/")
        for g in self.globs:
            g = g.rstrip("/")
            if (fnmatch.fnmatch(rel_path, g) or fnmatch.fnmatch(os.path.basename(rel_path), g)
                    or rel_path.startswith(g + "/")):
                return True
        return False


# ───────────────────────── 第 4 步：扫描目标 ─────────────────────────

def make_finding(path, lineno, rule, desc, secret, entropy, commit=None):
    return {"path": path, "line": lineno, "rule": rule, "description": desc,
            "secret": secret, "entropy": round(entropy, 2),
            "fingerprint": fingerprint(rule, secret), "commit": commit}


def is_config(path: str) -> bool:
    base = os.path.basename(path).lower()
    return base.startswith(".env") or os.path.splitext(base)[1] in CONFIG_EXTS


def scan_text(path, lines, opts, commit=None):
    """lines: [(行号, 文本)]"""
    lines = list(lines)
    hits = scan_lines([t for _, t in lines], config_file=is_config(path), use_entropy=opts.entropy,
                      entropy_threshold=opts.entropy_threshold)
    return [make_finding(path, lines[i][0], rule, desc, secret, h, commit)
            for i, rule, desc, secret, h in hits]


def read_text_file(path, max_size):
    """读文本文件；二进制（含 NUL 字节）或过大的文件返回 None。"""
    try:
        if os.path.getsize(path) > max_size:
            return None
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return None
    if b"\0" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def iter_files(roots, allow, base):
    for root in roots:
        if os.path.isfile(root):
            yield root
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS
                                 and not allow.path_ignored(os.path.relpath(os.path.join(dirpath, d), base)))
            for name in sorted(filenames):
                p = os.path.join(dirpath, name)
                if name in SKIP_FILES or os.path.islink(p):
                    continue
                yield p


def scan_paths(roots, opts, allow, base):
    findings = []
    for p in iter_files(roots, allow, base):
        rel = os.path.relpath(p, base)
        if allow.path_ignored(rel):
            continue
        text = read_text_file(p, opts.max_size)
        if text is None:
            continue
        findings += scan_text(rel, enumerate(text.splitlines(), 1), opts)
    return findings


def git(*args, cwd=None):
    r = subprocess.run(["git", *args], cwd=cwd, capture_output=True)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.decode(errors="replace").strip() or f"git {args[0]} 失败")
    return r.stdout.decode("utf-8", errors="replace")


HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def parse_diff(diff_text):
    """解析 `git diff -U0` 输出，只取新增的行。产出 (commit, 文件路径, [(行号, 文本)])。"""
    commit, path, lines, newno = None, None, [], 0
    for raw in diff_text.splitlines():
        if raw.startswith("COMMIT "):
            if path and lines:
                yield commit, path, lines
            commit, path, lines = raw.split()[1], None, []
        elif raw.startswith("diff --git "):
            if path and lines:
                yield commit, path, lines
            path, lines = None, []
        elif raw.startswith("+++ "):
            target = raw[4:]
            path = None if target == "/dev/null" else (target[2:] if target.startswith("b/") else target)
        elif raw.startswith("@@"):
            m = HUNK.match(raw)
            newno = int(m.group(1)) if m else 0
        elif raw.startswith("+") and path is not None:
            lines.append((newno, raw[1:]))
            newno += 1
    if path and lines:
        yield commit, path, lines


def scan_diff(diff_text, opts, allow):
    findings = []
    for commit, path, lines in parse_diff(diff_text):
        if allow.path_ignored(path) or os.path.basename(path) in SKIP_FILES:
            continue
        findings += scan_text(path, lines, opts, commit)
    return findings


def scan_staged(opts, allow, repo):
    diff = git("diff", "--cached", "-U0", "--no-color", "--no-ext-diff",
               "--diff-filter=ACMR", cwd=repo)
    return scan_diff(diff, opts, allow)


def scan_history(opts, allow, repo, max_count=None):
    args = ["log", "-p", "-U0", "--no-color", "--no-ext-diff", "--format=COMMIT %H"]
    args += ["--all"] if opts.all_refs else []
    if max_count:
        args.append(f"--max-count={max_count}")
    findings, seen = [], set()
    # 同一个秘密在多个提交里出现只报一次（最新的那次）
    for f in scan_diff(git(*args, cwd=repo), opts, allow):
        key = (f["path"], f["fingerprint"])
        if key not in seen:
            seen.add(key)
            findings.append(f)
    return findings


def repo_root(start="."):
    return git("rev-parse", "--show-toplevel", cwd=start).strip()


# ───────────────────────── 第 5 步：输出 ─────────────────────────

def apply_fp_allowlist(findings, allow):
    return [f for f in findings if f["fingerprint"] not in allow.fingerprints]


def report(findings, as_json=False, show_secrets=False, stream=None):
    stream = stream or sys.stdout
    if as_json:
        out = [{**f, "secret": f["secret"] if show_secrets else mask(f["secret"])} for f in findings]
        json.dump(out, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
        return
    for f in findings:
        where = f"{f['path']}:{f['line']}"
        if f["commit"]:
            where = f"{f['commit'][:8]} {where}"
        shown = f["secret"] if show_secrets else mask(f["secret"])
        print(f"[!] {where}  {f['rule']}  {shown}  fp:{f['fingerprint']}", file=stream)
        print(f"    {f['description']}", file=stream)
    if findings:
        print(f"⚠️  发现 {len(findings)} 处疑似密钥泄露。", file=stream)
        print("    确认是误报？在该行加注释 `secret-scan: allow`，"
              "或把 fp:<指纹> 写进 .secretsignore", file=stream)
    else:
        print("✅ 未发现疑似密钥。", file=stream)


# ───────────────────────── 第 6 步：pre-commit hook ─────────────────────────

HOOK_MARK = "# installed by secret_scan.py"


def hook_script(scanner_path):
    return (f"#!/bin/sh\n{HOOK_MARK}\n"
            f"# 跳过（不推荐）：git commit --no-verify\n"
            f"exec python3 \"{scanner_path}\" staged\n")


def install_hook(repo, force=False):
    hooks_dir = git("rev-parse", "--git-path", "hooks", cwd=repo).strip()
    if not os.path.isabs(hooks_dir):
        hooks_dir = os.path.join(repo, hooks_dir)
    os.makedirs(hooks_dir, exist_ok=True)
    hook = os.path.join(hooks_dir, "pre-commit")
    if os.path.exists(hook) and not force:
        with open(hook, encoding="utf-8", errors="replace") as f:
            if HOOK_MARK not in f.read():
                raise RuntimeError(f"{hook} 已存在且不是本工具安装的；用 --force 覆盖")
    with open(hook, "w", encoding="utf-8") as f:
        f.write(hook_script(os.path.abspath(__file__)))
    os.chmod(hook, 0o755)
    return hook


# ───────────────────────── 命令行 ─────────────────────────

def build_parser():
    p = argparse.ArgumentParser(description="密钥泄露扫描器：正则 + 香农熵，找出误提交的 API key / 密码")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--json", action="store_true", help="JSON 输出")
        sp.add_argument("--no-entropy", dest="entropy", action="store_false",
                        help="关闭纯熵检测（只用规则和敏感变量名）")
        sp.add_argument("--entropy-threshold", type=float, default=ENTROPY_THRESHOLD,
                        help=f"高熵字符串阈值，默认 {ENTROPY_THRESHOLD}")
        sp.add_argument("--ignore-file", help=f"allowlist 文件，默认 <根目录>/{IGNORE_FILE}")
        sp.add_argument("--show-secrets", action="store_true", help="输出完整秘密（危险，默认打码）")

    s = sub.add_parser("scan", help="扫描目录或文件")
    s.add_argument("paths", nargs="*", default=["."])
    s.add_argument("--max-size", type=int, default=MAX_FILE_SIZE, help="跳过大于此字节数的文件")
    common(s)

    st = sub.add_parser("staged", help="扫描 git 暂存区新增的行（pre-commit 用）")
    common(st)

    h = sub.add_parser("history", help="扫描 git 历史里新增过的行")
    h.add_argument("--max-count", type=int, help="只看最近 N 个提交")
    h.add_argument("--all", dest="all_refs", action="store_true", help="包括所有分支和 tag")
    common(h)

    i = sub.add_parser("install-hook", help="安装为当前仓库的 pre-commit hook")
    i.add_argument("--force", action="store_true", help="覆盖已有的 pre-commit hook")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.cmd == "install-hook":
            print(f"✅ 已安装：{install_hook(repo_root())}")
            return EXIT_CLEAN

        if args.cmd == "scan":
            base = os.path.abspath(args.paths[0] if os.path.isdir(args.paths[0]) else ".")
            for p in args.paths:
                if not os.path.exists(p):
                    raise RuntimeError(f"路径不存在：{p}")
        else:
            base = repo_root()
            args.max_size = MAX_FILE_SIZE
        allow = Allowlist.load(args.ignore_file or os.path.join(base, IGNORE_FILE))

        if args.cmd == "scan":
            findings = scan_paths(args.paths, args, allow, base)
        elif args.cmd == "staged":
            findings = scan_staged(args, allow, base)
        else:
            findings = scan_history(args, allow, base, args.max_count)
    except RuntimeError as e:
        print(f"错误：{e}", file=sys.stderr)
        return EXIT_ERROR

    findings = apply_fp_allowlist(findings, allow)
    report(findings, as_json=args.json, show_secrets=args.show_secrets)
    if findings and args.cmd == "staged" and not args.json:
        print("❌ 提交已阻止。移除秘密后重新 git add，或标记为误报。", file=sys.stderr)
    return EXIT_FOUND if findings else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
