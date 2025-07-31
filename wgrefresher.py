#!/usr/bin/env python3
"""
wgrefresher.py — Refresh WG-Gesucht ads by toggling activation on a schedule.

⚠️ Disclaimer
Automating interactions with websites may violate their Terms of Service.
Use this script at your own risk. No warranty is provided.

Features
- Runs without CLI args (reads .env if present; falls back to prompts)
- Cross-platform control via a local control server (127.0.0.1)
- `status` CLI (pretty by default), `status --watch` (keeps terminal open), `status --open` (Web UI), `status --json` (raw)
- Token-protected control
- Rotating log file & PID next to this script file
- Graceful stop on all OSes (`python wgrefresher.py stop` or via Web UI button)
- Retries, backoff, and re-login on 401/403
"""

import argparse
import getpass
import http.server
import json
import logging
import logging.handlers
import os
import platform
import re
import secrets
import signal
import socketserver
import stat
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from typing import Dict, Optional, List

import requests


# -------------------- Global State -------------------- #

class State:
    """Holds runtime state shared with the control server."""
    def __init__(self):
        self.stop_event = threading.Event()
        self.start_ts: Optional[float] = None
        self.last_run_ts: Optional[float] = None
        self.next_run_ts: Optional[float] = None
        self.interval_secs: Optional[int] = None
        self.cycles: int = 0
        self.last_errors: List[str] = []
        self.ad_ids: List[str] = []

STATE = State()


# -------------------- Paths & Files -------------------- #

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def user_state_dir() -> str:
    """Per-user dir for token/port (not logs/pid)."""
    if os.name == "nt":
        base = os.environ.get("APPDATA", os.path.expanduser("~"))
        return os.path.join(base, "wgrefresher")
    elif sys.platform == "darwin":
        return os.path.join(os.path.expanduser("~/Library/Application Support"), "wgrefresher")
    else:
        return os.path.join(os.path.expanduser("~/.config"), "wgrefresher")

def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)

def control_files() -> Dict[str, str]:
    d = user_state_dir()
    ensure_dir(d)
    return {
        "dir": d,
        "token": os.path.join(d, "control.token"),
        "port": os.path.join(d, "control.port"),
        "pid": os.path.join(SCRIPT_DIR, "wgrefresher.pid"),
        "log": os.path.join(SCRIPT_DIR, "wgrefresher.log"),
    }

def read_file_if_exists(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return None


# -------------------- Utilities -------------------- #

def load_env(path: Optional[str]) -> Dict[str, str]:
    """Very small .env reader: KEY=VALUE per line, ignores comments/blanks."""
    env = {}
    if not path or not os.path.exists(path):
        return env
    with open(path, "r", encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if not ln or ln.startswith("#") or "=" not in ln:
                continue
            k, v = ln.split("=", 1)
            env[k.strip()] = v.strip()
    return env

def read_secret(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()

def read_ids_from_file(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8") as f:
        return [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]

def collect_ad_ids(args, env: Dict[str, str]) -> List[str]:
    """Collect ad IDs from CLI, file, env/.env; require at least one."""
    ids: List[str] = []
    if getattr(args, "ad_id", None):
        ids += args.ad_id
    if getattr(args, "ad_id_file", None):
        ids += read_ids_from_file(args.ad_id_file)
    env_ids = env.get("AD_IDS") or os.environ.get("WG_AD_IDS")
    if env_ids:
        ids += [s for s in re.split(r"[,\s]+", env_ids) if s]
    ids = [i.strip() for i in ids if i.strip()]
    if not ids:
        raise SystemExit("No ad IDs found. Set AD_IDS in .env or provide --ad-id/--ad-id-file.")
    return list(dict.fromkeys(ids))  # dedupe, keep order

def setup_logging(log_file: Optional[str], verbose: bool):
    """Console + rotating file handler."""
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    handlers: List[logging.Handler] = []
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    handlers.append(sh)
    if log_file:
        fh = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=1_000_000, backupCount=5, encoding="utf-8"
        )
        fh.setFormatter(fmt)
        handlers.append(fh)
    logging.basicConfig(
        level=(logging.DEBUG if verbose else logging.INFO),
        handlers=handlers
    )

def write_pid(pid_path: str):
    with open(pid_path, "w") as f:
        f.write(str(os.getpid()))
    if os.name == "posix":
        os.chmod(pid_path, stat.S_IRUSR | stat.S_IWUSR)

def get_or_create_token(token_path: str) -> str:
    tok = read_file_if_exists(token_path)
    if tok:
        return tok
    tok = secrets.token_urlsafe(32)
    with open(token_path, "w", encoding="utf-8") as f:
        f.write(tok)
    if os.name == "posix":
        os.chmod(token_path, stat.S_IRUSR | stat.S_IWUSR)
    return tok

def iso_utc(ts: Optional[float]) -> Optional[str]:
    if ts is None:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))

def fmt_local(ts: Optional[float]) -> str:
    if ts is None:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))

def human_duration(seconds: Optional[float]) -> str:
    if seconds is None:
        return "-"
    seconds = int(round(seconds))
    neg = seconds < 0
    seconds = abs(seconds)
    parts = []
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60), ("s", 1)):
        if seconds >= size or (unit == "s" and not parts):
            n, seconds = divmod(seconds, size)
            parts.append(f"{n}{unit}")
    return ("-" if neg else "") + " ".join(parts)


# -------------------- WG-Gesucht Client -------------------- #

class WGGesuchtSession(requests.Session):
    """Minimal client for WG-Gesucht login and ad activation toggle."""
    def __init__(self, timeout: int = 20):
        super().__init__()
        self.timeout = timeout
        self.access_token: Optional[str] = None
        self.user_id: Optional[str] = None
        self.csrf_token: Optional[str] = None
        self.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:141.0) Gecko/20100101 Firefox/141.0",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest",
            "X-Client-Id": "wg_desktop_website",
            "X-Smp-Client": "WG-Gesucht",
            "Origin": "https://www.wg-gesucht.de",
            "Referer": "https://www.wg-gesucht.de/",
        })

    def _req(self, method: str, url: str, **kw):
        kw.setdefault("timeout", self.timeout)
        return super().request(method, url, **kw)

    def login(self, email: str, password: str) -> None:
        self._req("GET", "https://www.wg-gesucht.de/")
        r = self._req(
            "POST",
            "https://www.wg-gesucht.de/ajax/sessions.php?action=login",
            json={
                "login_email_username": email,
                "login_password": password,
                "login_form_auto_login": "1",
                "display_language": "de",
            },
        )
        if r.status_code != 200:
            raise RuntimeError(f"Login HTTP {r.status_code}")
        data = r.json()
        if not all(k in data for k in ("access_token", "user_id")):
            raise RuntimeError("Login failed (missing token).")
        self.access_token = data["access_token"]
        self.user_id = str(data["user_id"])
        self.csrf_token = data.get("csrf_token")

    def _auth_headers(self) -> Dict[str, str]:
        h = {
            "X-User-ID": self.user_id or "",
            "X-Authorization": f"Bearer {self.access_token or ''}",
            "X-Client-ID": "wg_desktop_website",
        }
        dev_ref = self.cookies.get("X-Dev-Ref-No", "")
        if dev_ref:
            h["X-Dev-Ref-No"] = dev_ref
        return h

    def toggle_activation(self, ad_id: str) -> None:
        if not self.user_id:
            raise RuntimeError("Not logged in.")
        api = f"https://www.wg-gesucht.de/api/offers/{ad_id}/users/{self.user_id}"
        payload = {"deactivated": "1", "csrf_token": self.csrf_token}
        r1 = self._req("PATCH", api, json=payload, headers=self._auth_headers())
        if r1.status_code in (401, 403):
            raise PermissionError("Unauthorized")
        payload["deactivated"] = "0"
        r2 = self._req("PATCH", api, json=payload, headers=self._auth_headers())
        if r2.status_code in (401, 403):
            raise PermissionError("Unauthorized")


# -------------------- Control Server -------------------- #

class ControlHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler providing / (web UI), /status (JSON), /stop (POST)."""
    server_version = "wgrefresher/1.1"
    token: str = ""
    httpd_ref: Optional[socketserver.TCPServer] = None

    def log_message(self, format: str, *args):
        logging.info("HTTP %s - " + format, self.address_string(), *args)

    def _auth(self) -> bool:
        tok = self.headers.get("Authorization", "")
        if tok.startswith("Bearer "):
            tok = tok[7:]
        return tok == self.token

    def _json(self, code: int, obj: Dict):
        data = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _html(self, code: int, html: str):
        data = html.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/":
            qs = urllib.parse.parse_qs(parsed.query)
            tok = (qs.get("token", [""])[0] or "")
            if tok != self.token:
                return self._html(
                    200,
                    "<h3>Unauthorized</h3><p>Open via <code>python wgrefresher.py status --open</code>.</p>",
                )
            # Minimalistic web UI with auto-refresh and a stop button.
            page = f"""<!doctype html><meta charset="utf-8">
<title>wgrefresher</title>
<style>
body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:24px;}}
pre{{background:#f5f5f5;padding:12px;border-radius:8px;overflow:auto;}}
button{{padding:8px 14px;border-radius:8px;border:1px solid #ccc;cursor:pointer}}
h1{{margin:0 0 12px}}
small{{color:#666}}
.grid{{display:grid;grid-template-columns: max-content 1fr; gap:8px 16px; align-items:center;}}
.kv{{font-family:ui-monospace, Menlo, Consolas, monospace}}
</style>
<h1>wgrefresher</h1>
<small>Control server UI</small>
<p><button id="stop">Stop service</button></p>
<div class="grid">
  <div class="kv">Status</div><div id="kv_status" class="kv">-</div>
  <div class="kv">PID</div><div id="kv_pid" class="kv">-</div>
  <div class="kv">Platform</div><div id="kv_platform" class="kv">-</div>
  <div class="kv">Uptime</div><div id="kv_uptime" class="kv">-</div>
  <div class="kv">Last run</div><div id="kv_last" class="kv">-</div>
  <div class="kv">Next run</div><div id="kv_next" class="kv">-</div>
  <div class="kv">Interval</div><div id="kv_interval" class="kv">-</div>
  <div class="kv">Cycles</div><div id="kv_cycles" class="kv">-</div>
  <div class="kv">Ads</div><div id="kv_ads" class="kv">-</div>
</div>
<h3>Recent errors</h3>
<pre id="errors">None</pre>
<h3>Raw JSON</h3>
<pre id="out">Loading…</pre>
<script>
const token = "{tok}";
function humanDuration(s){{
  if(s===null||s===undefined) return "-";
  s = Math.round(s); const neg = s<0; s = Math.abs(s);
  const parts=[], units=[["d",86400],["h",3600],["m",60],["s",1]];
  for(const [u,v] of units){{ if(s>=v || (u==="s" && parts.length===0)){{ parts.push(Math.floor(s/v)+u); s%=v; }} }}
  return (neg? "-":"")+parts.join(" ");
}}
function setKV(id, val){{ document.getElementById(id).textContent = val; }}
async function refresh(){{
  const r = await fetch('/status', {{headers:{{Authorization:'Bearer '+token}}}});
  const j = await r.json();
  document.getElementById('out').textContent = JSON.stringify(j, null, 2);
  setKV("kv_status", j.running ? "RUNNING" : "STOPPED");
  setKV("kv_pid", j.pid);
  setKV("kv_platform", j.platform);
  setKV("kv_uptime", humanDuration(j.uptime_secs) + (j.start_local ? " (since " + j.start_local + ")" : ""));
  const last = j.last_run_local ? j.last_run_local : "-";
  const next = j.next_run_local ? j.next_run_local : "-";
  setKV("kv_last", last + (j.since_last_secs!=null ? " ("+humanDuration(j.since_last_secs)+" ago)" : ""));
  setKV("kv_next", next + (j.until_next_secs!=null ? " (in "+humanDuration(j.until_next_secs)+")" : ""));
  setKV("kv_interval", j.interval_secs!=null ? j.interval_secs + " s" : "-");
  setKV("kv_cycles", j.cycles ?? "-");
  setKV("kv_ads", (j.ad_ids && j.ad_ids.length) ? j.ad_ids.join(", ") : "-");
  document.getElementById("errors").textContent = (j.last_errors && j.last_errors.length) ? j.last_errors.join("\\n") : "None";
}}
document.getElementById('stop').onclick = async () => {{
  await fetch('/stop', {{method:'POST', headers:{{Authorization:'Bearer '+token}}}});
  setTimeout(refresh, 500);
}};
refresh(); setInterval(refresh, 3000);
</script>"""
            return self._html(200, page)

        if parsed.path == "/status":
            if not self._auth():
                return self._json(401, {"error": "unauthorized"})
            now = time.time()
            start_ts = STATE.start_ts
            last_ts = STATE.last_run_ts
            next_ts = STATE.next_run_ts
            payload = {
                "running": not STATE.stop_event.is_set(),
                "pid": os.getpid(),
                "platform": platform.platform(),
                "ad_ids": STATE.ad_ids,
                "ads_total": len(STATE.ad_ids),
                "cycles": STATE.cycles,
                "interval_secs": STATE.interval_secs,
                "start_ts": start_ts,
                "start_iso": iso_utc(start_ts),
                "start_local": fmt_local(start_ts),
                "uptime_secs": (None if start_ts is None else now - start_ts),
                "last_run_ts": last_ts,
                "last_run_iso": iso_utc(last_ts),
                "last_run_local": fmt_local(last_ts),
                "since_last_secs": (None if last_ts is None else now - last_ts),
                "next_run_ts": next_ts,
                "next_run_iso": iso_utc(next_ts),
                "next_run_local": fmt_local(next_ts),
                "until_next_secs": (None if next_ts is None else next_ts - now),
                "now_ts": now,
                "now_iso": iso_utc(now),
                "last_errors": STATE.last_errors[-10:],
                "errors_count": len(STATE.last_errors),
            }
            return self._json(200, payload)

        return self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/stop":
            if not self._auth():
                return self._json(401, {"error": "unauthorized"})
            STATE.stop_event.set()
            threading.Thread(target=self.httpd_ref.shutdown, daemon=True).start()
            return self._json(200, {"ok": True})
        return self._json(404, {"error": "not found"})


def start_control_server(port: int, token: str) -> socketserver.TCPServer:
    """Construct a threaded HTTP server; caller runs serve_forever()."""
    class _HTTP(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True
        allow_reuse_address = True
    ControlHandler.token = token
    httpd = _HTTP(("127.0.0.1", port), ControlHandler)
    ControlHandler.httpd_ref = httpd
    logging.info("Control server listening on http://127.0.0.1:%d", port)
    return httpd


# -------------------- Worker -------------------- #

def worker_loop(session: WGGesuchtSession, username: str, password: str,
                ad_ids: List[str], interval: int, max_retries: int):
    """Main loop: login, toggle all ads, sleep; repeat until stop event is set."""
    STATE.ad_ids = ad_ids
    STATE.interval_secs = interval
    while not STATE.stop_event.is_set():
        STATE.last_run_ts = time.time()
        STATE.next_run_ts = STATE.last_run_ts + interval
        errors = []

        # Login with exponential backoff.
        for i in range(max_retries):
            try:
                session.login(username, password)
                logging.info("Login OK (user_id=%s).", session.user_id)
                break
            except Exception as e:
                wait = min(60, 2 ** i)
                logging.warning("Login error: %s (retry in %ss)", e, wait)
                if STATE.stop_event.wait(wait):
                    return
        else:
            msg = "Login permanently failed."
            logging.error(msg)
            errors.append(msg)

        # Toggle each ad with retries; re-login on 401/403.
        for ad in ad_ids:
            success = False
            for i in range(max_retries):
                try:
                    session.toggle_activation(ad)
                    logging.info("Ad %s refreshed.", ad)
                    success = True
                    break
                except PermissionError:
                    logging.warning("401/403 for %s – re-login…", ad)
                    session = WGGesuchtSession(timeout=session.timeout)
                    try:
                        session.login(username, password)
                    except Exception as e:
                        logging.error("Re-login failed: %s", e)
                except Exception as e:
                    wait = min(60, 2 ** i)
                    logging.warning("Error on %s: %s (retry in %ss)", ad, e, wait)
                    if STATE.stop_event.wait(wait):
                        return
            if not success:
                errors.append(f"Ad {ad}: all retries failed.")

        if errors:
            STATE.last_errors += errors

        STATE.cycles += 1

        # Sleep until next interval (interruptible).
        if STATE.stop_event.wait(interval):
            break

    logging.info("Worker stopped.")


# -------------------- CLI -------------------- #

def default_paths_and_values():
    files = control_files()
    default_env = ".env" if os.path.exists(".env") else None
    return files, default_env

def parse_args():
    """Subcommands:
       - serve (default if no args): start worker + control server
       - status [--watch|--open|--json]: pretty (default), watch, web UI, or raw JSON
       - stop: stop the running service
    """
    files, default_env = default_paths_and_values()
    p = argparse.ArgumentParser(description="WG-Gesucht ad refresher with local control server.", add_help=True)
    sub = p.add_subparsers(dest="cmd")

    # serve: can run without args (uses .env if present)
    serve = sub.add_parser("serve", help="Start the service (default).")
    serve.add_argument("--env-file", type=str, default=os.environ.get("WG_ENV_FILE", default_env))
    serve.add_argument("--interval", type=int, default=int(os.environ.get("WG_INTERVAL", 3600)))
    serve.add_argument("--timeout", type=int, default=int(os.environ.get("WG_TIMEOUT", 20)))
    serve.add_argument("--max-retries", type=int, default=int(os.environ.get("WG_MAX_RETRIES", 3)))
    serve.add_argument("--email-file", type=str, default=os.environ.get("WG_EMAIL_FILE"))
    serve.add_argument("--password-file", type=str, default=os.environ.get("WG_PASSWORD_FILE"))
    serve.add_argument("--ad-id", action="append")
    serve.add_argument("--ad-id-file", type=str, default=os.environ.get("WG_AD_ID_FILE"))
    serve.add_argument("--log-file", type=str, default=None)  # override default path if provided
    serve.add_argument("--control-port", type=int, default=int(os.environ.get("WG_CONTROL_PORT", 12701)))
    serve.add_argument("--verbose", action="store_true")

    # status: pretty/watch/open/json
    status = sub.add_parser("status", help="Show status; pretty by default.")
    status.add_argument("--watch", action="store_true", help="Keep printing status (every 2s).")
    status.add_argument("--open", action="store_true", help="Open Web UI in browser.")
    status.add_argument("--json", action="store_true", help="Print raw JSON response.")

    # stop: graceful stop
    sub.add_parser("stop", help="Stop the running service.")

    args = sys.argv[1:]
    if not args:
        # No args → implicit "serve"
        return p.parse_args(["serve"])
    return p.parse_args()


# -------------------- Main -------------------- #

def print_pretty_status(j: Dict[str, object]):
    """Human-readable, compact status for CLI."""
    def line(label, value):
        print(f"{label:<12} {value}")
    running = "RUNNING" if j.get("running") else "STOPPED"
    line("Service", f"{running}  (PID {j.get('pid','-')})")
    line("Platform", j.get("platform", "-"))
    # Uptime
    uptime = human_duration(j.get("uptime_secs"))
    start_local = j.get("start_local") or "-"
    line("Uptime", f"{uptime}  (since {start_local})")
    # Runs
    last_local = j.get("last_run_local") or "-"
    since_last = human_duration(j.get("since_last_secs"))
    line("Last run", f"{last_local}  ({since_last} ago)")
    next_local = j.get("next_run_local") or "-"
    until_next = human_duration(j.get("until_next_secs"))
    line("Next run", f"{next_local}  (in {until_next})")
    # Interval & cycles
    line("Interval", f"{j.get('interval_secs','-')} s")
    line("Cycles", j.get("cycles", "-"))
    # Ads
    ids = j.get("ad_ids") or []
    line("Ads", ", ".join(ids) if ids else "-")
    # Errors
    errs = j.get("last_errors") or []
    if errs:
        print("Errors      ")
        for e in errs:
            print(f"  - {e}")
    else:
        line("Errors", "None")

def main():
    files, default_env = default_paths_and_values()
    args = parse_args()

    if args.cmd in (None, "serve"):
        env = load_env(getattr(args, "env_file", None))

        # Logging next to the script (cross-platform).
        log_file = getattr(args, "log_file", None) or files["log"]
        setup_logging(log_file, getattr(args, "verbose", False))
        write_pid(files["pid"])

        # Credentials & ad IDs (with fallbacks).
        try:
            username = (
                (read_secret(args.email_file) if getattr(args, "email_file", None) else None)
                or env.get("EMAIL")
                or os.environ.get("WG_EMAIL")
                or input("username: ")
            )
            password = (
                (read_secret(args.password_file) if getattr(args, "password_file", None) else None)
                or env.get("PASSWORD")
                or os.environ.get("WG_PASSWORD")
                or getpass.getpass("password: ")
            )
            ad_ids = collect_ad_ids(args, env)
        except Exception as e:
            logging.error("%s", e)
            sys.exit(1)

        # Control token/port files.
        token = get_or_create_token(files["token"])
        port = getattr(args, "control_port", 12701)
        with open(files["port"], "w", encoding="utf-8") as f:
            f.write(str(port))

        # Start control server (main thread) and worker (background).
        httpd = start_control_server(port, token)
        STATE.start_ts = time.time()
        session = WGGesuchtSession(timeout=getattr(args, "timeout", 20))
        worker = threading.Thread(
            target=worker_loop,
            args=(session, username, password, ad_ids, getattr(args, "interval", 3600), getattr(args, "max_retries", 3)),
            daemon=True,
        )
        worker.start()

        logging.info("Service started.")
        logging.info("Log file: %s", files["log"])
        logging.info("PID file: %s", files["pid"])
        logging.info("Open Web UI with: python wgrefresher.py status --open")

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            STATE.stop_event.set()
            httpd.shutdown()
            httpd.server_close()
            try:
                os.remove(files["pid"])
            except Exception:
                pass
            logging.info("Service stopped.")
            return

    elif args.cmd in ("status", "stop"):
        # Client mode: read port/token files and call local server.
        port_str = read_file_if_exists(files["port"])
        token = read_file_if_exists(files["token"])
        if not port_str or not token:
            print("No running service found (port/token missing).")
            sys.exit(1)
        port = int(port_str)

        if args.cmd == "status" and getattr(args, "open", False):
            url = f"http://127.0.0.1:{port}/?token={token}"
            webbrowser.open_new_tab(url)
            print(f"Opened: {url}")
            sys.exit(0)

        def fetch_status() -> Dict[str, object]:
            url = f"http://127.0.0.1:{port}/status"
            req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                return json.loads(resp.read().decode("utf-8"))

        if args.cmd == "status" and getattr(args, "watch", False):
            try:
                while True:
                    os.system("cls" if os.name == "nt" else "clear")
                    j = fetch_status()
                    if getattr(args, "json", False):
                        print(json.dumps(j, indent=2))
                    else:
                        print_pretty_status(j)
                    time.sleep(2)
            except KeyboardInterrupt:
                pass
            sys.exit(0)

        if args.cmd == "status":
            j = fetch_status()
            if getattr(args, "json", False):
                print(json.dumps(j, indent=2))
            else:
                print_pretty_status(j)
            sys.exit(0)

        # stop:
        url = f"http://127.0.0.1:{port}/stop"
        req = urllib.request.Request(url, method="POST", headers={"Authorization": f"Bearer {token}"})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                print("Stop signal sent.")
        except urllib.error.URLError as e:
            print("Failed to send stop:", e)
            sys.exit(2)
        sys.exit(0)


if __name__ == "__main__":
    main()
