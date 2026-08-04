"""
security_scanner_free.py — Enhanced security scanner for bot hosting panel.

Detects:
  - System intrusion / path traversal
  - File theft / exfiltration
  - Unauthorized file reading of system paths
  - Backdoors, obfuscation, resource abuse

Place this file in the SAME directory as bot.py.
The panel auto-imports:  from security_scanner_free import scan_file as _scan_file
"""

from __future__ import annotations

import ast as _ast
import os
import re
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ═══════════════════════════════════════════════════════════════════
#  PATTERN LIBRARY  (stronger than built-in)
# ═══════════════════════════════════════════════════════════════════

_SEC_PATTERNS: Dict[str, List[Tuple[str, str]]] = {
    # ── Data theft / system file access ──────────────────────────
    "🔴 Data Theft": [
        # os.walk / listdir / scandir on system roots
        (r'os\.(?:walk|listdir|scandir)\s*\(\s*["\'][/\\](?:root|home|etc|var|proc|sys|usr|opt|boot)["\']?',
         "System directory ကို စကင်/ဖတ်နေတယ်"),
        (r'os\.(?:walk|listdir|scandir)\s*\(\s*["\'][/\\]["\']',
         "Root (/) directory ကို စကင်နေတယ်"),
        # open() on absolute system paths
        (r'(?:open|Path)\s*\(\s*["\'][/\\](?:etc|root|home|proc|sys|var/log|var/lib)[/\\]',
         "System path ဖိုင်ကို ဖွင့်/ဖတ်နေတယ်"),
        (r'open\s*\(\s*["\'][/\\](?:etc/passwd|etc/shadow|etc/hosts|root/)',
         "အရေးကြီး system ဖိုင်ကို ဖတ်နေတယ်"),
        # shutil copy/move from system
        (r'shutil\.(?:copy|copy2|copytree|move|copyfile)\s*\([^)]*["\'][/\\](?:root|etc|home|var)',
         "System ဖိုင်ကို copy/move လုပ်နေတယ်"),
        # glob from root
        (r'glob\.glob\s*\(\s*["\'][/\\]',
         "Root မှ glob နဲ့ ဖိုင်ရှာနေတယ်"),
        (r'Path\s*\(\s*["\'][/\\]["\']\s*\)\s*\.rglob',
         "Root မှ rglob နဲ့ ဖိုင်အားလုံး ရှာနေတယ်"),
        # ZIP packing system trees
        (r'zipfile\.ZipFile.*["\']w["\'].*(?:os\.walk|rglob|glob)',
         "ဖိုင်တွေကို ZIP pack လုပ်နေတယ် (exfil ဖြစ်နိုင်)"),
        # Telegram send of opened files from absolute paths
        (r'send_(?:document|file|photo|video|audio)\s*\([^)]*open\s*\(\s*["\'][/\\]',
         "System ဖိုင်ကို Telegram မှတစ်ဆင့် ပို့နေတယ်"),
        (r'send_document\s*\([^)]*(?:/etc/|/root/|/home/|/proc/|/var/)',
         "System path ဖိုင်ကို document အဖြစ် ပို့နေတယ်"),
        # requests/urllib POST of file contents
        (r'open\s*\(\s*["\'][/\\](?:root|etc|proc|sys|home|var)[^\'"]*["\'][^)]*\).*(?:requests|urllib|httpx).*(?:post|put)',
         "System ဖိုင်ဖတ်ပြီး ပြင်ပကို ပို့နေတယ်"),
        (r'(?:requests|httpx|urllib).*(?:post|put).*(?:open|read|Path)\s*\([^)]*["\'][/\\]',
         "ဖိုင်အကြောင်းအရာကို HTTP ဖြင့် ပို့နေတယ်"),
        # Explicit root targeting
        (r'(?:ROOT_DIR|BASE_DIR|TARGET_DIR|SCAN_DIR)\s*=\s*["\'][/\\]["\']',
         "Root directory ကို target လုပ်နေတယ်"),
        # Reading other users' homes / panel storage
        (r'["\'][/\\]home[/\\][^/\'"]+[/\\]',
         "အခြား user home directory ကို access လုပ်နေတယ်"),
        (r'storage[/\\](?:encfiles|bot_data|data|keycache)',
         "Panel internal storage ကို ဖတ်/ခိုးယူနေတယ်"),
        # pathlib read of absolute paths
        (r'Path\s*\(\s*["\'][/\\](?:etc|root|home|proc|sys)',
         "Path နဲ့ system directory ကို ချိတ်နေတယ်"),
        # base64 encode then send (classic exfil)
        (r'base64\.b64encode\s*\(.*(?:read|open|Path)',
         "ဖိုင်ကို base64 encode လုပ်နေတယ် (exfil pattern)"),
    ],

    # ── Backdoors / arbitrary code execution ─────────────────────
    "🔴 Backdoor": [
        (r'subprocess\s*\.\s*(?:Popen|call|run|check_output|check_call)\s*\([^\n]*shell\s*=\s*True',
         "shell=True နဲ့ subprocess — command injection အန္တရာယ်"),
        (r'os\.(?:system|popen|exec[lv]e?|spawn)\s*\(',
         "os.system/popen/exec — arbitrary command run"),
        (r'marshal\.loads\s*\(',
         "Marshalled bytecode — obfuscated execution"),
        (r'ctypes\.(?:CDLL|cdll|windll)',
         "ctypes နဲ့ native library load — low-level abuse"),
        (r'socket\.socket\s*\(.*\)[\s\S]{0,80}\.connect\s*\(',
         "Raw socket connect — reverse shell ဖြစ်နိုင်"),
        (r'(?:pty|pexpect)\.(?:spawn|fork)',
         "PTY spawn — interactive shell backdoor"),
        # Node.js equivalents
        (r'child_process\.(?:exec|execSync|spawn|spawnSync)\s*\(',
         "Node child_process — arbitrary command"),
        (r'require\s*\(\s*["\']child_process["\']\s*\)',
         "child_process require — command execution"),
        (r'eval\s*\(\s*(?:atob|Buffer\.from|require)',
         "eval + decode — hidden remote code"),
    ],

    # ── Exposed credentials ──────────────────────────────────────
    "🔴 Exposed Credentials": [
        # Token regex handled separately
    ],

    # ── Obfuscation ──────────────────────────────────────────────
    "🟡 Obfuscation": [
        (r'base64\.b64decode\s*\([^)]+\)\s*(?:\)\s*)?(?:exec|eval|compile)',
         "Base64 decode + execute — hidden code"),
        (r'(?:\\x[0-9a-fA-F]{2}){8,}',
         "Long hex-encoded string — obfuscated payload"),
        (r'zlib\.decompress\s*\([^)]+\)\s*(?:\)\s*)?(?:exec|eval)',
         "Compressed + executed hidden code"),
        (r'codecs\.decode\s*\([^)]*["\']hex["\']',
         "Hex decode — possible obfuscation"),
        (r'getattr\s*\(\s*(?:__builtins__|builtins)\s*,',
         "getattr(__builtins__) — obfuscated builtin access"),
        (r'compile\s*\([^)]+\)[\s\n]*(?:exec|eval)\s*\(',
         "compile + exec/eval — dynamic code"),
    ],

    # ── Suspicious network ───────────────────────────────────────
    "🟡 Suspicious Network": [
        (r'devil-api\.com|elementfx\.io|grabify\.link|ip-api\.com/json',
         "သံသယဖြစ်ဖွယ် / malicious endpoint"),
        (r'pastebin\.com/raw|hastebin\.com|ghostbin\.|rentry\.co',
         "Paste site raw fetch — remote code load ဖြစ်နိုင်"),
        (r'ngrok\.io|localtunnel\.me|serveo\.net|cloudflared',
         "Tunnel service — data exfil channel ဖြစ်နိုင်"),
        (r'discord(?:app)?\.com/api/webhooks',
         "Discord webhook — silent data dump ဖြစ်နိုင်"),
    ],

    # ── Resource abuse ───────────────────────────────────────────
    "🟠 Resource Abuse": [
        (r'multiprocessing\.Pool\s*\(\s*(?:None|\d{3,})',
         "Massive process pool — resource abuse"),
        (r'(?:os\.fork\s*\(\s*\)\s*){2,}|while\s+True\s*:\s*os\.fork',
         "Fork bomb pattern"),
        (r'while\s+True\s*:[^\n]*(?:requests|urllib|httpx).*(?:get|post)',
         "Infinite network loop — resource abuse"),
    ],
}

_SEC_TOKEN_RE = re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b")

# Absolute system path prefixes we treat as sensitive
_SENSITIVE_PREFIXES = (
    "/root", "/etc", "/proc", "/sys", "/var/log", "/var/lib",
    "/home/", "/usr/local", "/boot", "/opt",
)


# ═══════════════════════════════════════════════════════════════════
#  STATIC SCAN
# ═══════════════════════════════════════════════════════════════════

def _sec_static_scan(code: str) -> Dict[str, List[str]]:
    results: Dict[str, List[str]] = {}
    for category, pattern_list in _SEC_PATTERNS.items():
        hits: List[str] = []
        for pattern, description in pattern_list:
            if re.search(pattern, code, re.IGNORECASE | re.MULTILINE):
                hits.append(description)
        if hits:
            results[category] = hits

    tokens = _SEC_TOKEN_RE.findall(code)
    if tokens:
        results.setdefault("🔴 Exposed Credentials", [])
        results["🔴 Exposed Credentials"].append(
            f"Bot Token တွေ့ရှိ: {tokens[0][:15]}..."
        )
    return results


# ═══════════════════════════════════════════════════════════════════
#  AST SCAN  (deeper structural analysis)
# ═══════════════════════════════════════════════════════════════════

def _is_sensitive_path(val: str) -> bool:
    if not isinstance(val, str):
        return False
    v = val.replace("\\", "/")
    if v in ("/", "/."):
        return True
    return any(v == p or v.startswith(p + "/") or v.startswith(p)
               for p in _SENSITIVE_PREFIXES)


def _sec_ast_scan(code: str) -> List[str]:
    findings: List[str] = []
    try:
        tree = _ast.parse(code)
    except SyntaxError as e:
        findings.append(f"Code parse မရပါ: {e} — encode/obfuscate လုပ်ထားနိုင်")
        return findings

    for node in _ast.walk(tree):
        if not isinstance(node, _ast.Call):
            continue
        func = node.func

        # ── Attribute calls: os.walk, os.listdir, open, shutil.*, etc.
        if isinstance(func, _ast.Attribute):
            attr = func.attr
            owner = ""
            if isinstance(func.value, _ast.Name):
                owner = func.value.id

            # os.walk / listdir / scandir with sensitive path
            if owner == "os" and attr in ("walk", "listdir", "scandir", "chdir"):
                if node.args:
                    arg0 = node.args[0]
                    if isinstance(arg0, _ast.Constant) and isinstance(arg0.value, str):
                        if _is_sensitive_path(arg0.value):
                            findings.append(
                                f"os.{attr}('{arg0.value}') — sensitive directory scan"
                            )

            # open() with sensitive path
            if attr == "open" or (isinstance(func.value, _ast.Name) is False and attr == "open"):
                pass  # handled below via Name

            # shutil.copy* / move with sensitive source
            if owner == "shutil" and attr in (
                "copy", "copy2", "copytree", "move", "copyfile", "rmtree"
            ):
                for arg in node.args[:1]:
                    if isinstance(arg, _ast.Constant) and isinstance(arg.value, str):
                        if _is_sensitive_path(arg.value):
                            findings.append(
                                f"shutil.{attr}('{arg.value}') — system file manipulation"
                            )

            # subprocess with shell=True
            if owner == "subprocess" and attr in (
                "Popen", "call", "run", "check_output", "check_call"
            ):
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, _ast.Constant):
                        if kw.value.value is True:
                            findings.append(
                                f"subprocess.{attr}(shell=True) — command injection risk"
                            )

            # Path(...).read_text / read_bytes on sensitive
            if attr in ("read_text", "read_bytes", "open", "write_bytes", "write_text"):
                # check if receiver is Path("sensitive")
                if isinstance(func.value, _ast.Call):
                    inner = func.value
                    if isinstance(inner.func, _ast.Name) and inner.func.id == "Path":
                        if inner.args and isinstance(inner.args[0], _ast.Constant):
                            if isinstance(inner.args[0].value, str) and _is_sensitive_path(inner.args[0].value):
                                findings.append(
                                    f"Path('{inner.args[0].value}').{attr}() — system file access"
                                )

        # ── Name calls: open(), eval(), exec(), __import__()
        if isinstance(func, _ast.Name):
            fname = func.id

            # open("/etc/...")
            if fname == "open" and node.args:
                arg0 = node.args[0]
                if isinstance(arg0, _ast.Constant) and isinstance(arg0.value, str):
                    if _is_sensitive_path(arg0.value):
                        findings.append(
                            f"open('{arg0.value}') — system file read"
                        )

            # eval / exec with dynamic argument
            if fname in ("eval", "exec"):
                if node.args:
                    arg0 = node.args[0]
                    if isinstance(arg0, (_ast.Call, _ast.Attribute, _ast.BinOp, _ast.JoinedStr)):
                        findings.append(
                            f"Dangerous: {fname}() — dynamic code execution"
                        )
                    elif isinstance(arg0, _ast.Name):
                        findings.append(
                            f"Dangerous: {fname}(variable) — dynamic code execution"
                        )

            # __import__('os') dynamic
            if fname == "__import__" and node.args:
                if isinstance(node.args[0], _ast.Constant) and node.args[0].value == "os":
                    findings.append("Dynamic __import__('os') — code injection vector")

            # compile(..., 'exec') then likely exec
            if fname == "compile":
                findings.append("compile() — dynamic code construction")

    return findings


# ═══════════════════════════════════════════════════════════════════
#  RISK + VERDICT
# ═══════════════════════════════════════════════════════════════════

def _sec_calculate_risk(static_findings: dict, ast_findings: List[str]) -> int:
    weights = {
        "🔴 Data Theft":          45,
        "🔴 Backdoor":            45,
        "🔴 Exposed Credentials": 10,
        "🟡 Suspicious Network":  15,
        "🟡 Obfuscation":         12,
        "🟠 Resource Abuse":      10,
    }
    score = sum(
        weights.get(cat, 5) * min(len(hits), 3)
        for cat, hits in static_findings.items()
        if hits
    )
    unique_ast = list(dict.fromkeys(ast_findings))
    # AST hits on sensitive paths are high-signal
    ast_bonus = 0
    for f in unique_ast:
        fl = f.lower()
        if any(k in fl for k in ("system file", "sensitive", "os.walk", "os.listdir",
                                  "dynamic code", "shell=true", "command injection")):
            ast_bonus += 12
        else:
            ast_bonus += 5
    score += min(ast_bonus, 40)
    return min(score, 100)


def _sec_get_verdict(risk_score: int, static_findings: dict, ast_findings: List[str]) -> Tuple[str, str]:
    has_blocking = any(
        static_findings.get(c)
        for c in ("🔴 Data Theft", "🔴 Backdoor")
    )
    # AST-confirmed system file access is also blocking
    has_ast_block = any(
        any(k in f.lower() for k in (
            "system file", "sensitive directory", "os.walk", "os.listdir",
            "command injection", "shell=true", "dynamic code execution",
        ))
        for f in ast_findings
    )
    has_credentials = bool(static_findings.get("🔴 Exposed Credentials"))

    if (has_blocking or has_ast_block) and risk_score >= 50:
        return "DANGEROUS", "REJECT"
    if risk_score >= 75:
        return "DANGEROUS", "REJECT"
    if has_blocking or has_ast_block:
        return "SUSPICIOUS", "MANUAL_REVIEW"
    if has_credentials and risk_score < 40:
        return "SUSPICIOUS", "MANUAL_REVIEW"
    if risk_score >= 45:
        return "SUSPICIOUS", "MANUAL_REVIEW"
    return "SAFE", "APPROVE"


def _sec_scan_code(code: str, filename: str = "file.py") -> dict:
    sf = _sec_static_scan(code)
    af = _sec_ast_scan(code)
    risk = _sec_calculate_risk(sf, af)
    verdict, recommendation = _sec_get_verdict(risk, sf, af)
    all_threats: List[str] = (
        [f"{c}: {h}" for c, hits in sf.items() for h in hits] + af
    )
    if verdict == "DANGEROUS":
        summary = (
            f"⚠️ အန္တရာယ်ရှိဖိုင်! ခြိမ်းခြောက်မှု {len(all_threats)} ခု တွေ့ရှိ။ "
            "System ဖိုင်ဖတ်/ခိုးယူ သို့မဟုတ် backdoor ပုံစံ ပါဝင်နေသည်။"
        )
    elif verdict == "SUSPICIOUS":
        summary = "🔍 သံသယဖြစ်ဖွယ်ဖိုင်။ Admin မှ manual review လိုအပ်သည်။"
    else:
        summary = "✅ ဖိုင်ဘေးကင်းသည်။ အဓိကခြိမ်းခြောက်မှု မတွေ့ပါ။"
    return {
        "verdict": verdict,
        "risk_score": risk,
        "findings": sf,
        "ast_findings": af,
        "all_threats": all_threats,
        "recommendation": recommendation,
        "summary": summary,
        "filename": filename,
    }


def _sec_scan_archive(file_path: str) -> dict:
    tmp = tempfile.mkdtemp()
    try:
        if file_path.endswith(".zip"):
            with zipfile.ZipFile(file_path, "r") as z:
                for name in z.namelist():
                    if name.startswith("/") or ".." in name:
                        return {
                            "verdict": "DANGEROUS",
                            "risk_score": 99,
                            "findings": {"🔴 Zip Slip Attack": ["ZIP ထဲမှာ အန္တရာယ်ရှိ path ပါသည်!"]},
                            "ast_findings": [],
                            "recommendation": "REJECT",
                            "summary": "ZIP Slip attack တွေ့ရှိ — ဖိုင်ပိတ်လိုက်သည်။",
                            "all_threats": ["ZIP Slip / path traversal"],
                            "filename": os.path.basename(file_path),
                        }
                z.extractall(tmp)
        elif file_path.endswith((".tar.gz", ".tgz", ".tar")):
            with tarfile.open(file_path, "r:*") as t:
                t.extractall(tmp)
        else:
            return {
                "verdict": "SUSPICIOUS",
                "risk_score": 30,
                "findings": {},
                "ast_findings": [],
                "recommendation": "MANUAL_REVIEW",
                "summary": "မသိသော archive အမျိုးအစား။",
                "all_threats": [],
                "filename": os.path.basename(file_path),
            }

        py_files = list(Path(tmp).rglob("*.py"))
        js_files = list(Path(tmp).rglob("*.js"))
        scan_targets = (py_files + js_files)[:15]

        if not scan_targets:
            return {
                "verdict": "SUSPICIOUS",
                "risk_score": 20,
                "findings": {"🟡 Warning": ["Archive ထဲမှာ .py/.js ဖိုင် မရှိ"]},
                "ast_findings": [],
                "recommendation": "MANUAL_REVIEW",
                "summary": "Archive ထဲမှာ Python/JS ဖိုင် မတွေ့ပါ။",
                "all_threats": [],
                "filename": os.path.basename(file_path),
            }

        worst: Optional[dict] = None
        for f in scan_targets:
            try:
                result = _sec_scan_code(f.read_text(errors="ignore"), f.name)
                if worst is None or result["risk_score"] > worst["risk_score"]:
                    worst = result
            except Exception:
                continue
        return worst or {
            "verdict": "SAFE",
            "risk_score": 0,
            "recommendation": "APPROVE",
            "summary": "ဘေးကင်းသည်။",
            "all_threats": [],
            "filename": os.path.basename(file_path),
        }
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def scan_file(file_path: str) -> dict:
    """Main entry — scan any uploaded file before saving/running."""
    filename = os.path.basename(file_path)
    try:
        lower = filename.lower()
        if lower.endswith((".zip", ".tar.gz", ".tgz", ".tar")):
            return _sec_scan_archive(file_path)
        if lower.endswith((".py", ".pyc", ".pyo", ".js", ".ts", ".mjs")):
            with open(file_path, "r", errors="ignore") as fh:
                return _sec_scan_code(fh.read(), filename)
        return {
            "verdict": "SUSPICIOUS",
            "risk_score": 30,
            "findings": {"🟡 Warning": [f"Unknown file type: {filename}"]},
            "ast_findings": [],
            "recommendation": "MANUAL_REVIEW",
            "summary": f"ဖိုင်အမျိုးအစား '{filename}' ကို ခွင့်မပြုပါ။",
            "all_threats": [],
            "filename": filename,
        }
    except Exception as exc:
        return {
            "verdict": "ERROR",
            "risk_score": 50,
            "findings": {},
            "ast_findings": [],
            "recommendation": "MANUAL_REVIEW",
            "summary": f"Scan error: {exc}",
            "all_threats": [],
            "filename": filename,
        }


# Quick self-test when run directly
if __name__ == "__main__":
    samples = {
        "safe_bot.py": '''
import telebot
bot = telebot.TeleBot("123:AA")
@bot.message_handler(commands=["start"])
def start(m):
    bot.reply_to(m, "hi")
bot.infinity_polling()
''',
        "thief.py": '''
import os, zipfile
for root, dirs, files in os.walk("/etc"):
    print(root, files)
with open("/etc/passwd") as f:
    data = f.read()
''',
        "backdoor.py": '''
import subprocess
subprocess.run(user_input, shell=True)
eval(compile(payload, "<x>", "exec"))
''',
    }
    for name, code in samples.items():
        r = _sec_scan_code(code, name)
        print(f"{name}: {r['verdict']} risk={r['risk_score']} rec={r['recommendation']}")
        for t in r["all_threats"][:5]:
            print(f"  - {t}")
        print()
