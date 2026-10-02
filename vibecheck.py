#!/usr/bin/env python3
"""vibecheck - quick safety check for AI-generated code.

Usage:  python vibecheck.py [path]

Checks:
  1. Packages: does every imported package really exist on PyPI / npm?
     Is it suspiciously new?
  2. Hardcoded keys: API keys / secrets typed directly in code.

Only the Python standard library is used. No API key needed.
"""
import ast
import json
import math
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "env", "__pycache__",
             "dist", "build", ".next", ".idea", ".vscode"}
PY_EXT = {".py"}
JS_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
SCAN_EXT = PY_EXT | JS_EXT | {".json", ".yaml", ".yml", ".toml", ".ini",
                              ".cfg", ".sh", ".env", ".txt", ".md"}
MAX_FILE_BYTES = 1_000_000
NEW_PACKAGE_DAYS = 30

# import name -> real PyPI name (common mismatches)
PY_NAME_MAP = {
    "cv2": "opencv-python", "PIL": "pillow", "yaml": "pyyaml",
    "sklearn": "scikit-learn", "bs4": "beautifulsoup4",
    "dotenv": "python-dotenv", "dateutil": "python-dateutil",
    "jwt": "pyjwt", "OpenSSL": "pyopenssl", "serial": "pyserial",
    "attr": "attrs", "google": None, "skimage": "scikit-image",
    "Crypto": "pycryptodome", "telegram": "python-telegram-bot",
    "discord": "discord.py", "docx": "python-docx", "fitz": "pymupdf",
    "magic": "python-magic", "MySQLdb": "mysqlclient", "psycopg2": "psycopg2-binary",
}

NODE_BUILTINS = {
    "assert", "buffer", "child_process", "cluster", "console", "constants",
    "crypto", "dgram", "dns", "domain", "events", "fs", "http", "http2",
    "https", "inspector", "module", "net", "os", "path", "perf_hooks",
    "process", "punycode", "querystring", "readline", "repl", "stream",
    "string_decoder", "sys", "timers", "tls", "tty", "url", "util", "v8",
    "vm", "worker_threads", "zlib", "test",
}

# (name, regex) - style follows well known scanners (gitleaks / detect-secrets)
SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b")),
    ("Stripe live key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{20,}\b")),
    ("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    ("Telegram bot token", re.compile(r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b")),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("Database URL with password",
     re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s:/@]+:[^\s@]{3,}@")),
]

# api_key = "something long" style assignments
GENERIC_ASSIGN = re.compile(
    r"""(?ix)
    (?P<name>[\w\-]*(?:api[_\-]?key|secret|token|passwd|password|auth)[\w\-]*)
    \s*[:=]\s*
    ["'](?P<value>[^"'\s]{12,})["']
    """
)
PLACEHOLDER_HINTS = ("your", "xxx", "example", "changeme", "placeholder",
                     "<", "{", "$", "env", "todo", "dummy", "test", "***")


def entropy(s):
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in freq.values())


def mask(s):
    return s[:4] + "..." + s[-2:] if len(s) > 8 else "****"


def walk_files(root):
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            yield os.path.join(dirpath, fn)


def read_text(path):
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return None
        with open(path, "r", encoding="utf-8", errors="strict") as f:
            return f.read()
    except (OSError, UnicodeDecodeError):
        return None


# ---------------------------------------------------------------- secrets
def scan_secrets(files):
    findings = []
    for path in files:
        ext = os.path.splitext(path)[1].lower()
        base = os.path.basename(path)
        if ext not in SCAN_EXT and not base.startswith(".env"):
            continue
        # .env is the *right* place for keys; the problem is committing it
        if base.startswith(".env"):
            continue
        text = read_text(path)
        if text is None:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            hit = False
            for name, rx in SECRET_PATTERNS:
                m = rx.search(line)
                if m:
                    findings.append((path, lineno, name, mask(m.group(0))))
                    hit = True
                    break
            if hit:
                continue
            m = GENERIC_ASSIGN.search(line)
            if m:
                val = m.group("value")
                low = val.lower()
                if any(h in low for h in PLACEHOLDER_HINTS):
                    continue
                if entropy(val) >= 3.2:
                    findings.append((path, lineno,
                                     f"Possible secret in '{m.group('name')}'",
                                     mask(val)))
    return findings


# --------------------------------------------------------------- packages
def local_python_names(root):
    names = set()
    base = root if os.path.isdir(root) else os.path.dirname(root) or "."
    for entry in os.listdir(base):
        full = os.path.join(base, entry)
        if os.path.isdir(full):
            names.add(entry)
        elif entry.endswith(".py"):
            names.add(entry[:-3])
    return names


def python_imports(path):
    text = read_text(path)
    if text is None:
        return {}
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return {}
    found = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                found.setdefault(a.name.split(".")[0], node.lineno)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                found.setdefault(node.module.split(".")[0], node.lineno)
    return found


JS_IMPORT = re.compile(
    r"""(?:import\s+(?:[^'"]*?\s+from\s+)?|require\(\s*|import\(\s*)['"]([^'"]+)['"]""")


def js_imports(path):
    text = read_text(path)
    if text is None:
        return {}
    found = {}
    for lineno, line in enumerate(text.splitlines(), 1):
        for m in JS_IMPORT.finditer(line):
            spec = m.group(1)
            if spec.startswith((".", "/", "node:", "@/", "~")):
                continue
            parts = spec.split("/")
            pkg = "/".join(parts[:2]) if spec.startswith("@") else parts[0]
            if pkg in NODE_BUILTINS:
                continue
            found.setdefault(pkg, lineno)
    return found


def requirements_packages(path):
    text = read_text(path) or ""
    found = {}
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.split("#")[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        name = re.split(r"[<>=!~;\[ ]", line, maxsplit=1)[0]
        if name:
            found[name] = lineno
    return found


def http_json(url):
    """Returns (status, data). status: 200, 404, or None on network error."""
    req = urllib.request.Request(url, headers={"User-Agent": "vibecheck/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return 200, json.load(r)
    except urllib.error.HTTPError as e:
        return (404 if e.code == 404 else None), None
    except Exception:
        return None, None


def age_days(iso):
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).days
    except Exception:
        return None


def check_pypi(name):
    status, data = http_json(f"https://pypi.org/pypi/{name}/json")
    if status is None:
        return "error", None
    if status == 404:
        return "missing", None
    dates = [f["upload_time_iso_8601"]
             for files in data.get("releases", {}).values() for f in files]
    return "ok", age_days(min(dates)) if dates else None


def check_npm(name):
    status, data = http_json("https://registry.npmjs.org/" + name.replace("/", "%2F"))
    if status is None:
        return "error", None
    if status == 404:
        return "missing", None
    created = (data.get("time") or {}).get("created")
    return "ok", age_days(created) if created else None


def scan_packages(root, files):
    stdlib = set(getattr(sys, "stdlib_module_names", set())) | set(sys.builtin_module_names)
    local = local_python_names(root)
    # (ecosystem, pypi/npm name) -> (file, line)
    wanted = {}
    for path in files:
        ext = os.path.splitext(path)[1].lower()
        base = os.path.basename(path)
        if ext in PY_EXT:
            for mod, line in python_imports(path).items():
                if mod in stdlib or mod in local or mod == "__future__":
                    continue
                real = PY_NAME_MAP.get(mod, mod)
                if real:
                    wanted.setdefault(("pypi", real, mod), (path, line))
        elif base.startswith("requirements") and ext == ".txt":
            for name, line in requirements_packages(path).items():
                wanted.setdefault(("pypi", name, name), (path, line))
        elif ext in JS_EXT:
            for pkg, line in js_imports(path).items():
                wanted.setdefault(("npm", pkg, pkg), (path, line))

    problems, checked, offline = [], 0, 0
    for (eco, name, shown), (path, line) in sorted(wanted.items()):
        status, age = check_pypi(name) if eco == "pypi" else check_npm(name)
        checked += 1
        if status == "error":
            offline += 1
        elif status == "missing":
            problems.append((path, line, eco, name, shown, "missing", None))
        elif age is not None and age < NEW_PACKAGE_DAYS:
            problems.append((path, line, eco, name, shown, "new", age))
    return problems, checked, offline



# ------------------------------------------------------------- .env check
def env_not_ignored(root, files):
    """.env files that exist but are not covered by .gitignore."""
    import fnmatch
    base = root if os.path.isdir(root) else os.path.dirname(root) or "."
    patterns = []
    gi = os.path.join(base, ".gitignore")
    text = read_text(gi) if os.path.exists(gi) else ""
    for line in (text or "").splitlines():
        line = line.strip().lstrip("/")
        if line and not line.startswith(("#", "!")):
            patterns.append(line.rstrip("/"))
    risky = []
    for path in files:
        name = os.path.basename(path)
        if not name.startswith(".env") or name.endswith((".example", ".sample", ".template")):
            continue
        relp = os.path.relpath(path, base)
        ignored = any(fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(relp, pat)
                      for pat in patterns)
        if not ignored:
            risky.append(path)
    return risky

# ------------------------------------------------------------------ main
def rel(p):
    return os.path.relpath(p)


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    if not os.path.exists(root):
        print(f"Path nahi mila: {root}")
        return 2
    files = list(walk_files(root))
    print(f"\nvibecheck: {len(files)} files scan ho rahi hain...\n")
    bad = 0

    print("== 1. PACKAGES ==")
    problems, checked, offline = scan_packages(root, files)
    if offline == checked and checked:
        print("  Internet nahi mila, packages check nahi ho paaye.")
    for path, line, eco, name, shown, kind, age in problems:
        bad += 1
        site = "PyPI" if eco == "pypi" else "npm"
        where = f"{rel(path)}:{line}"
        if kind == "missing":
            print(f"  [!] {where}  '{name}' {site} pe exist nahi karta.")
            print("      AI ne naam bana diya ho sakta hai, aur koi attacker isi naam se")
            print("      malware daal sakta hai. Install karne se pehle sahi naam confirm karo.")
            if eco == "pypi" and shown != name:
                print(f"      (import '{shown}' ko '{name}' maana gaya)")
            elif eco == "pypi":
                print("      (Note: kabhi import ka naam aur pip ka naam alag hota hai.)")
        else:
            print(f"  [!] {where}  '{name}' sirf {age} din purana hai.")
            print("      Naye packages risky ho sakte hain. Check karo ki ye sahi/popular hai.")
    if not problems and not (offline == checked and checked):
        print(f"  OK: {checked} packages check kiye, sab theek lage.")

    print("\n== 2. HARDCODED KEYS ==")
    secrets = scan_secrets(files)
    for path, line, name, masked in secrets:
        bad += 1
        print(f"  [!] {rel(path)}:{line}  {name} ({masked})")
        print("      Key code mein mat likho. Isse .env file mein daalo, .env ko .gitignore")
        print("      mein rakho, aur agar GitHub pe gayi hai to key turant revoke/rotate karo.")
    if not secrets:
        print("  OK: koi hardcoded key nahi mili.")


    print("\n== 3. .env FILE ==")
    env_risky = env_not_ignored(root, files)
    for path in env_risky:
        bad += 1
        print(f"  [!] {rel(path)}  .gitignore mein nahi hai.")
        print("      Ye GitHub pe chali gayi to saari keys leak ho jayengi.")
        print("      .gitignore mein ye line daalo:  .env")
    if not env_risky:
        print("  OK: .env files surakshit hain (ya hain hi nahi).")

    print(f"\nResult: {bad} problem(s) mili.\n")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
