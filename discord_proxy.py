#!/usr/bin/env python3
"""
Discord Proxy - single-file Windows GUI
========================================

A thin GUI around sing-box (https://github.com/SagerNet/sing-box, the
open-source proxy engine - this script does not embed it, and downloads it
only if you confirm) that routes ONLY Discord's traffic - TCP and UDP/voice - through a
proxy you provide, while every other process (games, Steam, your browser,
Windows itself) stays on your normal connection, untouched.

    Discord.exe / DiscordPTB.exe / DiscordCanary.exe  -->  your proxy
    everything else                                    -->  DIRECT (ISP)

There is no system-wide proxy setting changed, no 0.0.0.0/0 route, and no
change to your default gateway - see build_singbox_config() below, which is
the entire routing logic, in plain sight.

--------------------------------------------------------------------------
REQUIREMENTS (if sing-box / wintun / xray are missing the app offers to download them
from the official sources - only after you confirm)
--------------------------------------------------------------------------
  1. Windows 10/11.
  2. Python 3.10+ from python.org (the "tcl/tk and IDLE" option must be
     included in the installer - it is by default). Check with:
         python --version
  3. sing-box.exe - an OFFICIAL release from
         https://github.com/SagerNet/sing-box/releases
     (download the windows-amd64 .zip, pull out sing-box.exe), placed in
     the SAME FOLDER as this script.
  4. wintun.dll - from the official project page https://www.wintun.net/
     (take the amd64 dll from the zip), placed in the same folder as this
     script. Needed for the TUN adapter that lets sing-box see Discord's
     UDP voice traffic per-process.
  5. Run this script as Administrator (creating a TUN adapter requires
     elevation). Right-click -> "Run as administrator", or use the
     in-app "Restart as Administrator" button.
  6. A proxy - a vless://, vmess://, trojan:// or ss:// link from a
     provider/server you already trust. This script doesn't include or
     recommend one.
  7. xray.exe - OPTIONAL, only needed if your link uses XHTTP
     (type=xhttp/splithttp in the link's query string). Vanilla sing-box
     has no XHTTP support at all, so this script runs a local Xray-core
     instance for XHTTP specifically and routes just that one connection
     through it - everything else still goes straight through sing-box.
     Official release: https://github.com/XTLS/Xray-core/releases
     (Xray-windows-64.zip -> xray.exe), placed in the same folder as this
     script. Every other transport (tcp/ws/grpc/http/httpupgrade) needs
     only sing-box.exe, same as before.

--------------------------------------------------------------------------
RUN
--------------------------------------------------------------------------
    python discord_proxy.py

Everything - link parsing, config generation, the sing-box (and, for XHTTP
links only, xray-core) process wrappers, and the GUI - lives in this one
file so there's nothing else to build or install beyond Python itself.
--------------------------------------------------------------------------
"""

from __future__ import annotations

import base64
import collections
import ctypes
import hashlib
import ipaddress
import glob
import json
import math
import os
import platform
import queue
import re
import secrets
import shutil
import signal
import subprocess
import sys
import struct
import threading
import time
import tkinter as tk
import urllib.error
import urllib.request
import webbrowser
import zipfile
import zlib
from datetime import datetime
from tkinter import filedialog, messagebox, simpledialog, ttk
from urllib.parse import urlsplit, parse_qsl, unquote
from xml.sax.saxutils import escape as xml_escape

# ============================================================================
# Paths / constants
# ============================================================================

OUTBOUND_TAG = "user-proxy"
DISCORD_PROCESS_NAMES = ["Discord.exe", "DiscordPTB.exe", "DiscordCanary.exe"]
# Resolved per Windows user: %LOCALAPPDATA% -> C:\Users\<current user>\AppData\Local
DISCORD_DEFAULT_PATH = os.path.join(
    os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Local"),
    "Discord", "Discord.exe")
RECOVER_MAX = 5          # automatic restarts allowed ...
RECOVER_WINDOW_S = 600   # ... within this many seconds, then it gives up
HEALTH_FAILS_NOTICE = 3    # consecutive failed probes before the status shows "not answering" (silent - no popup)
HEALTH_FAILS_RESTART = 12  # consecutive failed probes before the chain is restarted (~4 min). A weak link is
                           # NOT a dead proxy: restarting tears down the TUN adapter and every UDP flow, and
                           # a Discord voice call that lost its flow stays at ~5000 ms until rejoined.
VOICE_CHECK_WINDOW_S = 10  # after Discord joins a voice server, UDP media must be in the tunnel by then
WIN_WIDTH = 470                # fixed window width; the height is measured from the content
FAILOVER_FAILS = 5             # consecutive failed health probes before switching to the next saved link
FAILOVER_MEMORY_S = 600        # a link that just failed is skipped for this long when picking the next one
HISTORY_WINDOW_S = 3600        # connection history graph window
SIDE_WIDTH = 520               # right-hand pane: server list, connection graph, live log
TOTAL_WIDTH = WIN_WIDTH + SIDE_WIDTH
HIST_H = 96
PROBE_DEST = ("1.0.0.1", 53)   # voice-quality probe target (a DNS query); never learned as a Discord range
PROBE_INBOUND_TAG = "probe-in"
AUTOSTART_TASK = "DiscordProxy"
UPDATE_CHECK_INTERVAL_S = 12 * 3600


# ============================================================================
# Secrets: masking in the log + Windows DPAPI protection of the saved link
# ============================================================================

_SECRETS: set = set()
_SECRET_KEYS = {"id", "uuid", "password", "privatekey", "private_key", "secretkey", "presharedkey",
                "pre_shared_key", "psk", "seed", "encryption", "pinnedpeercertsha256", "auth", "secret",
                "_encryption", "_pcs"}
_UUID_RE = re.compile(r"\b([0-9a-fA-F]{8})-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
_HEX64_RE = re.compile(r"\b([0-9a-fA-F]{8})[0-9a-fA-F]{56}\b")
_MLKEM_RE = re.compile(r"mlkem768x25519plus(?:\.[A-Za-z0-9_\-+=]+)+")
_LINK_RE = re.compile(r"\b(vless|vmess|trojan|ss|hysteria2|hy2|tuic|wireguard|wg)://\S+", re.I)
_KV_RE = re.compile(r"(?i)([\"']?(?:password|private_?key|secret_?key|pre_?shared_?key|psk|obfs-password|obfs_password)[\"']?\s*[:=]\s*[\"']?)([^\"'\s,}&]{4,})")


def register_secrets(node) -> None:
    """Remembers every secret inside a parsed outbound so mask_secrets() can
    hide it wherever it shows up (log lines, error messages, exports)."""
    def add(v):
        if isinstance(v, str) and len(v) >= 6 and v.lower() != "none":
            _SECRETS.add(v)
            # mlkem768x25519plus.native.0rtt.<KEY>: tools may print only the KEY part
            for seg in v.split("."):
                if len(seg) >= 16:
                    _SECRETS.add(seg)

    def walk(n, key=""):
        if isinstance(n, dict):
            for k, v in n.items():
                walk(v, str(k).lower())
        elif isinstance(n, (list, tuple)):
            for v in n:
                walk(v, key)
        elif key in _SECRET_KEYS:
            add(n)

    walk(node)


def _mask_value(v: str) -> str:
    return v[:3] + "***"


def mask_secrets(text: str) -> str:
    """Hides UUIDs, passwords, keys, pinned-cert hashes and whole proxy links."""
    if not text:
        return text
    text = _LINK_RE.sub(lambda m: m.group(1).lower() + "://***hidden***", text)
    for s in sorted(_SECRETS, key=len, reverse=True):
        if s in text:
            text = text.replace(s, _mask_value(s))
    text = _MLKEM_RE.sub("mlkem768x25519plus.***", text)
    text = _UUID_RE.sub(lambda m: m.group(1) + "-****-****", text)
    text = _HEX64_RE.sub(lambda m: m.group(1) + "...(hash hidden)", text)
    text = _KV_RE.sub(lambda m: m.group(1) + _mask_value(m.group(2)), text)
    return text


# --- Windows DPAPI: the saved link is encrypted for THIS Windows user account ---

_LINK_STATE = {"encrypted": False, "failed": False}
_DPAPI_PREFIX = "dpapi:"


def _dpapi(data: bytes, encrypt: bool):
    """CryptProtectData / CryptUnprotectData via ctypes. None when unavailable."""
    if os.name != "nt":
        return None
    try:
        from ctypes import wintypes

        class _Blob(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

        buf = ctypes.create_string_buffer(data, len(data))
        src = _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
        dst = _Blob()
        crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        if encrypt:
            ok = crypt32.CryptProtectData(ctypes.byref(src), "DiscordProxy", None, None, None, 1, ctypes.byref(dst))
        else:
            ok = crypt32.CryptUnprotectData(ctypes.byref(src), None, None, None, None, 1, ctypes.byref(dst))
        if not ok:
            return None
        try:
            return ctypes.string_at(dst.pbData, dst.cbData)
        finally:
            kernel32.LocalFree(dst.pbData)
    except Exception:
        return None


def protect_link(text: str):
    blob = _dpapi(text.encode("utf-8"), True)
    return (_DPAPI_PREFIX + base64.b64encode(blob).decode("ascii")) if blob else None


def unprotect_link(value: str):
    if not isinstance(value, str) or not value.startswith(_DPAPI_PREFIX):
        return None
    try:
        blob = _dpapi(base64.b64decode(value[len(_DPAPI_PREFIX):]), False)
    except Exception:
        return None
    return blob.decode("utf-8") if blob else None


def scrub_runtime_configs(include_tests: bool = True) -> None:
    """The generated sing-box/xray configs contain the proxy credentials in
    plain text. They are only needed while the proxy runs, so remove them.
    include_tests=False leaves the Test Proxy button's own temp files alone
    (a test may be running right now; it removes them itself when it finishes)."""
    paths = [generated_config_path(), xray_config_path()]
    if include_tests:
        paths += [os.path.join(config_dir(), "test.json"), xray_test_config_path(),
                  testall_config_path(), xray_testall_config_path()]
    for path in paths:
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass


import atexit
atexit.register(scrub_runtime_configs)


try:                       # captured at import: __file__ is gone while the interpreter shuts down
    _SCRIPT_PATH = os.path.abspath(__file__)
except NameError:
    _SCRIPT_PATH = os.path.abspath(sys.argv[0] or "discord_proxy.py")


def base_dir() -> str:
    """Folder this script (or its frozen .exe, if built with PyInstaller) lives in."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(_SCRIPT_PATH)


def singbox_exe_path() -> str:
    return os.path.join(base_dir(), "sing-box.exe")


def wintun_dll_path() -> str:
    return os.path.join(base_dir(), "wintun.dll")


def config_dir() -> str:
    return os.path.join(base_dir(), "dp_data")


def generated_config_path() -> str:
    return os.path.join(config_dir(), "generated.json")


def settings_path() -> str:
    return os.path.join(config_dir(), "settings.json")


_SETTING_CHOICES = {
    "theme": ("auto", "light", "dark"),
    "capture_mode": ("all", "discord"),
    "strict_route": ("auto", "on", "off"),
    "close_action": ("ask", "tray", "exit"),
    "core": ("auto", "singbox", "xray"),
    "tun_stack": ("mixed", "system", "gvisor"),
    "tun_mtu": ("9000", "1500", "1400"),
}
_GEOMETRY_RE = re.compile(r"(\d+)x(\d+)(?:\+(-?\d+)\+(-?\d+))?")


def settings_backup_path() -> str:
    return settings_path() + ".bak"


def sanitize_settings(data: dict) -> dict:
    """Drops values that no longer make sense (hand-edited or corrupted file)
    so a bad entry can never crash the UI - it just falls back to its default."""
    out = dict(data)
    for key, allowed in _SETTING_CHOICES.items():
        if key in out and out[key] not in allowed:
            del out[key]
    for key in ("notifications", "auto_mode", "failover", "autostart", "autostart_delay", "show_log_panel",
                "log_open", "history_open", "check_updates", "voice_probe", "kill_switch"):
        if key in out and not isinstance(out[key], bool):
            out[key] = bool(out[key])
    if "autostart_delay_s" in out:
        try:
            out["autostart_delay_s"] = max(5, min(600, int(out["autostart_delay_s"])))
        except (TypeError, ValueError):
            del out["autostart_delay_s"]
    if "links" in out:
        out["links"] = sanitize_links(out["links"])
    if "links_enc" in out and not isinstance(out["links_enc"], str):
        del out["links_enc"]
    if "update_notified" in out and not isinstance(out["update_notified"], dict):
        del out["update_notified"]
    if "link" in out and not isinstance(out["link"], str):
        del out["link"]
    if "link_enc" in out and not isinstance(out["link_enc"], str):
        del out["link_enc"]
    if "geometry" in out and not (isinstance(out["geometry"], str) and _GEOMETRY_RE.fullmatch(out["geometry"])):
        del out["geometry"]
    return out


def _read_json_dict(path: str):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def load_settings() -> dict:
    """Settings from the last run. If settings.json is missing or damaged the
    previous good copy (settings.json.bak) is used."""
    for path in (settings_path(), settings_backup_path()):
        data = _read_json_dict(path)
        if data is not None:
            data = sanitize_settings(data)
            enc = data.pop("link_enc", None)
            if enc:
                plain = unprotect_link(enc)
                if plain is not None:
                    data["link"] = plain
                    _LINK_STATE["encrypted"] = True
                else:
                    _LINK_STATE["failed"] = True  # other Windows account / machine, or damaged
            enc_links = data.pop("links_enc", None)
            if enc_links:
                try:
                    plain_links = unprotect_link(enc_links)
                    data["links"] = sanitize_links(json.loads(plain_links)) if plain_links else []
                    if not plain_links:
                        _LINK_STATE["failed"] = True
                except Exception:
                    _LINK_STATE["failed"] = True
            return data
    return {}


def save_settings(data: dict) -> None:
    """Atomic write (a crash mid-save can't leave a half-written file) and the
    previous good file is kept as settings.json.bak."""
    try:
        os.makedirs(config_dir(), exist_ok=True)
        path = settings_path()
        tmp = path + ".tmp"
        data = dict(data)
        data.pop("link_enc", None)
        data.pop("links_enc", None)
        if data.get("links"):
            enc_links = protect_link(json.dumps(data["links"], ensure_ascii=False))
            if enc_links:                      # saved links are encrypted for this Windows user too
                data["links_enc"] = enc_links
                del data["links"]
            else:
                _LINK_STATE["encrypted"] = False
        if data.get("link"):
            enc = protect_link(data["link"])
            _LINK_STATE["encrypted"] = bool(enc)
            if enc:  # the plain text never reaches the disk
                data["link_enc"] = enc
                del data["link"]
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        if _read_json_dict(path) is not None:
            try:
                shutil.copy2(path, settings_backup_path())
            except OSError:
                pass
        os.replace(tmp, path)
        if "link_enc" in data or "links_enc" in data:  # an older backup may still hold links unencrypted
            bak = _read_json_dict(settings_backup_path())
            if bak is not None and ("link" in bak or "links" in bak):
                try:
                    shutil.copy2(path, settings_backup_path())
                except OSError:
                    pass
    except OSError:
        pass


def reset_saved_data() -> list:
    """Deletes everything the app saved between runs: settings (and their
    backup), the generated sing-box config and the learned Discord ranges. A
    hand-edited ranges file is kept as discord_ranges.txt.bak. Returns the
    names of what was removed."""
    removed = []
    for path in (settings_path(), settings_backup_path(), settings_path() + ".tmp",
                 generated_config_path(), xray_config_path(), os.path.join(config_dir(), "test.json"),
                 xray_test_config_path(), testall_config_path(), xray_testall_config_path(),
                 learned_ranges_path()):
        try:
            if os.path.exists(path):
                os.remove(path)
                removed.append(os.path.basename(path))
        except OSError:
            pass
    manual = manual_ranges_path()
    try:
        if os.path.exists(manual):
            with open(manual, "r", encoding="utf-8") as f:
                edited = f.read() != _RANGES_TEMPLATE
            if edited:
                os.replace(manual, manual + ".bak")
                removed.append(os.path.basename(manual) + " (kept as .bak)")
            else:
                os.remove(manual)
                removed.append(os.path.basename(manual))
    except OSError:
        pass
    return removed


def fmt_bytes(n: float) -> str:
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{int(n)} B" if unit == "B" else f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} GB"


_ANSI_RE = re.compile(r"(?:\x1b)?\[[0-9;]+m")


def strip_ansi(line: str) -> str:
    return _ANSI_RE.sub("", line)


def xray_exe_path() -> str:
    return os.path.join(base_dir(), "xray.exe")


def xray_config_path() -> str:
    return os.path.join(config_dir(), "xray.json")


def xray_test_config_path() -> str:
    """Separate file for the 'Test Proxy' button, so a test never touches the live xray.json."""
    return os.path.join(config_dir(), "xray_test.json")


def testall_config_path() -> str:
    return os.path.join(config_dir(), "test_all.json")


def xray_testall_config_path() -> str:
    return os.path.join(config_dir(), "xray_test_all.json")


def downloads_dir() -> str:
    return os.path.join(config_dir(), "downloads")


# ============================================================================
# Admin / elevation helpers
# ============================================================================

def is_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> bool:
    """Re-launches this script elevated via UAC. Returns True if the elevated
    process was launched (the caller should exit); False if the user
    cancelled the UAC prompt or it otherwise failed."""
    if os.name != "nt":
        return False
    try:
        script = _SCRIPT_PATH
        params = " ".join(f'"{a}"' for a in sys.argv[1:])
        args = f'"{script}" {params}'.strip()
        result = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, args, base_dir(), 1)
        # ShellExecuteW returns a value > 32 on success.
        return int(result) > 32
    except Exception:
        return False


# ============================================================================
# Proxy link parsing: vless:// / vmess:// / trojan:// / ss:// / raw JSON
#   -> a sing-box outbound dict tagged "user-proxy"
#
# This only ever reads a server address/credentials the user pastes in; it
# never contacts any server on its own and never sends the parsed data
# anywhere except into the local config file handed to sing-box.exe.
# ============================================================================

class ParseError(Exception):
    pass


def _b64decode_flexible(s: str) -> bytes:
    s = s.strip().replace("-", "+").replace("_", "/")
    pad = len(s) % 4
    if pad == 2:
        s += "=="
    elif pad == 3:
        s += "="
    elif pad != 0:
        raise ParseError("Invalid base64 length.")
    return base64.b64decode(s)


def _query_dict(query: str) -> dict:
    return {k: v for k, v in parse_qsl(query, keep_blank_values=True)}


def _apply_tls(ob: dict, q: dict, default_sni: str) -> None:
    security = q.get("security", "")
    if not security or security == "none":
        return

    tls = {"enabled": True, "server_name": q.get("sni") or default_sni}

    alpn = q.get("alpn", "")
    if alpn:
        tls["alpn"] = [a.strip() for a in alpn.split(",") if a.strip()]

    fp = q.get("fp", "")
    if fp:
        tls["utls"] = {"enabled": True, "fingerprint": fp}

    if _truthy(q.get("allowInsecure")) or _truthy(q.get("insecure")):
        tls["insecure"] = True

    if security == "reality":
        reality = {"enabled": True}
        if q.get("pbk"):
            reality["public_key"] = q["pbk"]
        if q.get("sid"):
            reality["short_id"] = q["sid"]
        tls["reality"] = reality

    ob["tls"] = tls


def _build_transport_for_net(net: str, path: str, host: str, q: dict | None = None):
    net = (net or "tcp").lower()
    q = q or {}
    if net == "ws":
        ws = {"type": "ws", "path": path or "/"}
        # "/ws?ed=2048" is the Xray convention for websocket early data;
        # sing-box wants that as separate fields, not part of the path.
        m = re.search(r"[?&]ed=(\d+)", ws["path"])
        if m:
            ws["max_early_data"] = int(m.group(1))
            ws["early_data_header_name"] = "Sec-WebSocket-Protocol"
            ws["path"] = re.sub(r"[?&]ed=\d+", "", ws["path"]).rstrip("?&") or "/"
        if host:
            ws["headers"] = {"Host": host}
        return ws
    if net == "httpupgrade":
        hu = {"type": "httpupgrade", "path": path or "/"}
        if host:
            hu["host"] = host
        return hu
    if net == "grpc":
        return {"type": "grpc", "service_name": (path or "").lstrip("/")}
    if net in ("http", "h2"):
        h2 = {"type": "http", "path": path or "/"}
        if host:
            h2["host"] = [host]
        return h2
    if net in ("tcp", ""):
        return None
    if net in ("kcp", "mkcp"):
        # mKCP: sing-box has no KCP at all, so this goes through Xray-core (see needs_xray()).
        return {"type": "kcp", "header": q.get("headerType") or "none", "seed": q.get("seed") or ""}
    if net == "quic":
        # sing-box QUIC transport (needs a sing-box build with the quic tag; Xray removed QUIC).
        return {"type": "quic"}
    if net in ("xhttp", "splithttp"):
        # Marked, not built here - vanilla sing-box has no XHTTP support at
        # all (confirmed against its own transport switch), so this outbound
        # gets routed through a local Xray-core instance instead. See
        # xray_outbound_from_parsed() / uses_xhttp() below for where this
        # marker is actually consumed.
        return {"type": "xhttp", "path": path or "/", "host": host or ""}
    # kcp / quic / ...: silently falling back to plain TCP would make the
    # server answer with confusing HTTP errors (e.g. 403).
    raise ParseError(
        f'Transport "{net}" is not supported by this tool. Paste a sing-box '
        "or Xray outbound JSON instead, or use a link with type=tcp/ws/grpc/http/httpupgrade/xhttp/kcp/quic."
    )


def _apply_transport(ob: dict, q: dict) -> None:
    net = q.get("type", "")  # v2ray/sing-box share-link convention calls this "type"
    if not net or net == "tcp":
        return
    path = q.get("path", "")
    if net.lower() == "grpc" and q.get("serviceName"):
        path = q["serviceName"]
    transport = _build_transport_for_net(net, path, q.get("host", ""), q)
    if transport is not None:
        if transport.get("type") == "xhttp":
            transport["mode"] = q.get("mode", "auto")
            extra = q.get("extra", "")
            if extra:
                transport["extra"] = extra
        ob["transport"] = transport


def _parse_raw_json(text: str) -> dict:
    try:
        node = json.loads(text)
    except json.JSONDecodeError as ex:
        raise ParseError(f"Invalid JSON: {ex}")
    if not isinstance(node, dict):
        raise ParseError("The pasted JSON is not an object.")
    if "type" not in node:
        raise ParseError('The pasted JSON object is missing a "type" field (e.g. "vless", "vmess", "trojan", "shadowsocks").')
    if "server" not in node or "server_port" not in node:
        raise ParseError('The pasted JSON object needs "server" and "server_port" fields.')
    node["tag"] = OUTBOUND_TAG
    return node


def _parse_vless(link: str) -> dict:
    parts = urlsplit(link)
    uuid = unquote(parts.username or "")
    host = parts.hostname or ""
    port = parts.port or 443
    q = _query_dict(parts.query)

    if not uuid:
        raise ParseError("VLESS link is missing a UUID (expected vless://UUID@host:port?...).")
    if not host:
        raise ParseError("VLESS link is missing a host.")

    ob = {
        "type": "vless",
        "tag": OUTBOUND_TAG,
        "server": host,
        "server_port": port,
        "uuid": uuid,
        "packet_encoding": "xudp",
    }
    flow = q.get("flow", "")
    if flow:
        ob["flow"] = flow

    _apply_tls(ob, q, default_sni=host)
    _apply_transport(ob, q)
    enc = q.get("encryption", "")
    if enc and enc != "none":
        ob["_encryption"] = enc  # VLESS encryption (e.g. mlkem768x25519plus...), Xray-only
    _apply_xray_extras(ob, q)
    ob["_ignored"] = _unknown_params(q, _known_for_net(q, ("encryption", "flow")))
    return ob


def _parse_vmess(link: str) -> dict:
    payload = link[len("vmess://"):].split("#", 1)[0]
    try:
        raw = _b64decode_flexible(payload).decode("utf-8")
        doc = json.loads(raw)
    except Exception as ex:
        raise ParseError(f"Could not decode the vmess:// link: {ex}")
    if not isinstance(doc, dict):
        raise ParseError("vmess:// payload did not decode to a JSON object.")

    host = str(doc.get("add", "") or "")
    port = int(doc.get("port", 443) or 443)
    uuid = str(doc.get("id", "") or "")
    net = str(doc.get("net", "tcp") or "tcp").lower()
    security = str(doc.get("scy") or doc.get("security") or "auto")
    alter_id = int(doc.get("aid", 0) or 0)
    tls_field = str(doc.get("tls", "") or "").lower()
    sni = str(doc.get("sni", "") or host)
    path = str(doc.get("path", "") or "/")
    host_header = str(doc.get("host", "") or host)

    if not host or not uuid:
        raise ParseError('vmess:// link is missing "add" (server) or "id" (uuid).')

    ob = {
        "type": "vmess",
        "tag": OUTBOUND_TAG,
        "server": host,
        "server_port": port,
        "uuid": uuid,
        "security": security or "auto",
        "alter_id": alter_id,
    }
    if tls_field == "tls":
        ob["tls"] = {"enabled": True, "server_name": sni}
        if doc.get("alpn"):
            ob["tls"]["alpn"] = [a.strip() for a in str(doc["alpn"]).split(",") if a.strip()]
        if doc.get("fp"):
            ob["tls"]["utls"] = {"enabled": True, "fingerprint": str(doc["fp"])}
        if _truthy(doc.get("allowInsecure")):
            ob["tls"]["insecure"] = True

    transport = _build_transport_for_net(net, path, host_header,
                                         {"headerType": doc.get("type") or "none", "seed": doc.get("path") or ""})
    if transport is not None:
        if transport.get("type") == "xhttp":
            transport["mode"] = str(doc.get("mode", "") or "auto")
        ob["transport"] = transport
    vm_known = {"v", "ps", "add", "port", "id", "aid", "scy", "security", "net", "type", "host", "path",
                "tls", "sni", "alpn", "fp", "mode", "allowInsecure"}
    ob["_ignored"] = sorted(k for k, v in doc.items() if k not in vm_known and v not in ("", None, 0, "0"))
    return ob


def _parse_trojan(link: str) -> dict:
    parts = urlsplit(link)
    password = unquote(parts.username or "")
    host = parts.hostname or ""
    port = parts.port or 443
    q = _query_dict(parts.query)

    if not password:
        raise ParseError("trojan:// link is missing a password (expected trojan://PASSWORD@host:port?...).")
    if not host:
        raise ParseError("trojan:// link is missing a host.")

    ob = {
        "type": "trojan",
        "tag": OUTBOUND_TAG,
        "server": host,
        "server_port": port,
        "password": password,
    }

    security = q.get("security", "")
    if not security or security in ("tls", "reality"):
        _apply_tls(ob, q, default_sni=host)

    _apply_transport(ob, q)
    _apply_xray_extras(ob, q)
    ob["_ignored"] = _unknown_params(q, _known_for_net(q))
    return ob


def _parse_shadowsocks(link: str) -> dict:
    ob = _parse_shadowsocks_core(link)
    # ss://...?plugin=obfs-local;... is NOT supported - say so instead of silently dropping it
    ob["_ignored"] = sorted(_query_dict(urlsplit(link).query))
    return ob


def _parse_shadowsocks_core(link: str) -> dict:
    body = link[len("ss://"):].split("#", 1)[0]

    if "@" in body:
        # SIP002: base64(method:password)@host:port
        user_info_raw, host_part = body.rsplit("@", 1)
        host_part = re.split(r"[/?]", host_part, 1)[0]
        try:
            user_info = _b64decode_flexible(user_info_raw).decode("utf-8")
        except Exception:
            user_info = unquote(user_info_raw)  # some generators leave it plain
        if ":" not in user_info:
            raise ParseError("Could not read method/password from the ss:// link.")
        method, password = user_info.split(":", 1)
    else:
        # legacy: whole method:password@host:port is base64
        try:
            decoded = _b64decode_flexible(body).decode("utf-8")
        except Exception as ex:
            raise ParseError(f"Could not base64-decode the ss:// link: {ex}")
        if "@" not in decoded:
            raise ParseError("ss:// link did not decode into method:password@host:port.")
        user_info, host_part = decoded.rsplit("@", 1)
        if ":" not in user_info:
            raise ParseError("Could not read method/password from the ss:// link.")
        method, password = user_info.split(":", 1)

    if ":" in host_part:
        host, port_str = host_part.split(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            port = 8388
    else:
        host, port = host_part, 8388

    return {
        "type": "shadowsocks",
        "tag": OUTBOUND_TAG,
        "server": host,
        "server_port": port,
        "method": method,
        "password": password,
    }


# ----------------------------------------------------------------------------
# More protocols (hysteria2 / tuic / wireguard), raw Xray JSON, ignored-param report
# ----------------------------------------------------------------------------

def _unknown_params(q: dict, known) -> list:
    """Query parameters in the link that this tool does not use (names only)."""
    known_l = {k.lower() for k in known}
    return sorted(k for k in q if k.lower() not in known_l)


def _truthy(v) -> bool:
    return str(v or "").strip().lower() in ("1", "true", "yes")


def _hostport(netloc: str):
    hp = netloc.rsplit("@", 1)[-1]
    if hp.startswith("["):
        host, _, rest = hp[1:].partition("]")
        port_s = rest.lstrip(":")
    else:
        host, _, port_s = hp.partition(":")
    return host, port_s


def _ports(port_s: str, mport: str = ""):
    """('443', '20000-30000') -> (443, ['443:443', '20000:30000']) - port hopping ranges."""
    nums = re.findall(r"\d+", port_s or "")
    port = int(nums[0]) if nums else 443
    ranges = []
    for seg in ((port_s or "") + "," + (mport or "")).split(","):
        a, sep, b = seg.strip().partition("-")
        if sep and a.isdigit() and b.isdigit():
            ranges.append(f"{a}:{b}")
    if ranges:
        ranges.insert(0, f"{port}:{port}")
    return port, ranges


def _simple_tls(q: dict, host: str, default_alpn=None) -> dict:
    tls = {"enabled": True, "server_name": q.get("sni") or q.get("peer") or host}
    alpn = q.get("alpn", "")
    if alpn:
        tls["alpn"] = [a.strip() for a in alpn.split(",") if a.strip()]
    elif default_alpn:
        tls["alpn"] = list(default_alpn)
    if _truthy(q.get("insecure")) or _truthy(q.get("allowInsecure")) or _truthy(q.get("allow_insecure")):
        tls["insecure"] = True
    return tls


def _parse_hysteria2(link: str) -> dict:
    parts = urlsplit(link)
    q = _query_dict(parts.query)
    userinfo, _, hostport = parts.netloc.rpartition("@")
    password = unquote(userinfo)
    host, port_s = _hostport(hostport)
    if not password:
        raise ParseError("hysteria2:// link is missing the password (expected hysteria2://PASSWORD@host:port?...).")
    if not host:
        raise ParseError("hysteria2:// link is missing a host.")
    port, ranges = _ports(port_s, q.get("mport", ""))
    ob = {"type": "hysteria2", "tag": OUTBOUND_TAG, "server": host, "server_port": port,
          "password": password, "tls": _simple_tls(q, host)}
    if ranges:
        ob.pop("server_port")
        ob["server_ports"] = ranges
    if q.get("obfs"):
        if q["obfs"].lower() != "salamander":
            raise ParseError(f'hysteria2 obfs type "{q["obfs"]}" is not supported (only "salamander").')
        ob["obfs"] = {"type": "salamander", "password": q.get("obfs-password") or q.get("obfs_password", "")}
    ob["_ignored"] = _unknown_params(q, ("sni", "peer", "insecure", "allowInsecure", "allow_insecure", "obfs",
                                         "obfs-password", "obfs_password", "mport", "alpn"))
    return ob


def _parse_tuic(link: str) -> dict:
    parts = urlsplit(link)
    q = _query_dict(parts.query)
    userinfo, _, hostport = parts.netloc.rpartition("@")
    uuid, _, password = userinfo.partition(":")
    uuid, password = unquote(uuid), unquote(password)
    host, port_s = _hostport(hostport)
    if not uuid or not password:
        raise ParseError("tuic:// link needs UUID:PASSWORD (expected tuic://UUID:PASSWORD@host:port?...).")
    if not host:
        raise ParseError("tuic:// link is missing a host.")
    port = int(port_s) if port_s.isdigit() else 443
    ob = {"type": "tuic", "tag": OUTBOUND_TAG, "server": host, "server_port": port,
          "uuid": uuid, "password": password, "tls": _simple_tls(q, host, default_alpn=("h3",))}
    if q.get("congestion_control"):
        ob["congestion_control"] = q["congestion_control"]
    if q.get("udp_relay_mode"):
        ob["udp_relay_mode"] = q["udp_relay_mode"]
    if _truthy(q.get("udp_over_stream")):
        ob["udp_over_stream"] = True
    ob["_ignored"] = _unknown_params(q, ("sni", "peer", "insecure", "allowInsecure", "allow_insecure", "alpn",
                                         "congestion_control", "udp_relay_mode", "udp_over_stream"))
    return ob


def _parse_wireguard(link: str) -> dict:
    m = re.match(r"^(?:wireguard|wg)://([^@]+)@([^?#]+)(?:\?([^#]*))?", link.strip(), re.I)
    if not m:
        raise ParseError("WireGuard link should look like wireguard://PRIVATE_KEY@host:port"
                         "?publickey=...&address=10.0.0.2/32")
    private_key = unquote(m.group(1))
    # NOT parse_qsl: base64 keys contain '+' which must stay a '+'
    q = {}
    for kv in (m.group(3) or "").split("&"):
        k, sep, v = kv.partition("=")
        if sep:
            q[k] = unquote(v)
    host, port_s = _hostport(m.group(2).rstrip("/"))
    port = int(port_s) if port_s.isdigit() else 51820
    pub = q.get("publickey") or q.get("public_key") or q.get("peer_public_key") or ""
    addr = q.get("address") or q.get("ip") or ""
    if not host:
        raise ParseError("WireGuard link is missing the server host.")
    if not pub:
        raise ParseError("WireGuard link is missing publickey= (the server's public key).")
    if not addr:
        raise ParseError("WireGuard link is missing address= (your tunnel IP, e.g. 10.0.0.2/32).")
    addresses = []
    for a in addr.split(","):
        a = a.strip()
        if a:
            addresses.append(a if "/" in a else (a + ("/128" if ":" in a else "/32")))
    peer = {"address": host, "port": port, "public_key": pub, "allowed_ips": ["0.0.0.0/0", "::/0"]}
    psk = q.get("presharedkey") or q.get("psk")
    if psk:
        peer["pre_shared_key"] = psk
    if q.get("reserved"):
        try:
            res = [int(x) for x in q["reserved"].split(",")]
        except ValueError:
            raise ParseError("WireGuard reserved= must be three numbers like 1,2,3.")
        if len(res) == 3:
            peer["reserved"] = res
    ob = {"type": "wireguard", "tag": OUTBOUND_TAG, "address": addresses,
          "private_key": private_key, "peers": [peer], "_server": host, "_server_port": port}
    if q.get("mtu", "").isdigit():
        ob["mtu"] = int(q["mtu"])
    ob["_ignored"] = _unknown_params(q, ("publickey", "public_key", "peer_public_key", "address", "ip", "mtu",
                                         "reserved", "presharedkey", "psk"))
    return ob


_XRAY_SECRET_KEYS = ("id", "password", "privatekey", "secretkey", "encryption", "pinnedpeercertsha256")


def _looks_like_xray(node: dict) -> bool:
    if "protocol" in node and "type" not in node:
        return True
    outs = node.get("outbounds")
    return isinstance(outs, list) and any(isinstance(o, dict) and "protocol" in o for o in outs)


def _xray_endpoint(node: dict):
    st = node.get("settings") or {}
    try:
        for key in ("vnext", "servers"):
            lst = st.get(key)
            if isinstance(lst, list) and lst and isinstance(lst[0], dict):
                return str(lst[0].get("address", "")), int(lst[0].get("port", 0) or 0)
        return str(st.get("address", "")), int(st.get("port", 0) or 0)
    except (TypeError, ValueError):
        return "", 0


def _parse_raw_xray(node: dict) -> dict:
    """A pasted Xray outbound object, or a full Xray config (its first real
    proxy outbound is used). Passed to xray-core exactly as written, so every
    option works: XHTTP downloadSettings, xmux, headers, Reality spiderX, ..."""
    if isinstance(node.get("outbounds"), list):
        cands = [o for o in node["outbounds"] if isinstance(o, dict) and "protocol" in o
                 and str(o["protocol"]).lower() not in ("freedom", "blackhole", "dns", "loopback")]
        tagged = [o for o in cands if o.get("tag") == "proxy"]
        picked = (tagged or cands or [None])[0]
        if picked is None:
            raise ParseError("The pasted Xray config has no proxy outbound (only freedom/blackhole/dns).")
        node = picked
    if "protocol" not in node:
        raise ParseError('The pasted Xray JSON needs a "protocol" field (e.g. "vless").')
    node = json.loads(json.dumps(node))
    server, port = _xray_endpoint(node)
    return {"type": "xray-raw", "tag": OUTBOUND_TAG, "server": server, "server_port": port,
            "_xray_outbound": node}


def _apply_xray_extras(ob: dict, q: dict) -> None:
    """Link options only Xray understands (underscore keys are stripped before
    sing-box sees the outbound, same as _encryption)."""
    pcs = [x.strip() for x in q.get("pcs", "").split(",") if x.strip()]
    if pcs:
        ob["_pcs"] = pcs  # pinned peer cert sha256 list
    if q.get("vcn"):
        ob["_vcn"] = q["vcn"]  # verifyPeerCertByName
    if _truthy(q.get("allowInsecure", q.get("insecure", ""))):
        ob["_insecure"] = True
    if q.get("spx"):
        ob["_spx"] = q["spx"]  # Reality spiderX
    if q.get("pqv"):
        ob["_pqv"] = q["pqv"]  # Reality mldsa65Verify
    xpb = q.get("x_padding_bytes", "")
    if xpb and (ob.get("transport") or {}).get("type") == "xhttp":
        try:
            ex = json.loads(ob["transport"].get("extra") or "{}")
        except ValueError:
            ex = {}
        ex.setdefault("xPaddingBytes", xpb)
        ob["transport"]["extra"] = json.dumps(ex)


_COMMON_KNOWN = ("security", "sni", "alpn", "fp", "pbk", "sid", "type", "path", "host", "mode", "extra",
                 "allowInsecure", "insecure", "serviceName", "pcs", "vcn", "x_padding_bytes", "spx", "pqv")


def _known_for_net(q: dict, extra=()):
    known = list(_COMMON_KNOWN) + list(extra)
    if (q.get("type") or "").lower() in ("kcp", "mkcp"):
        known += ["headerType", "seed"]
    return known


def parse_proxy_link(text: str):
    """Returns (outbound_dict, None) on success, or (None, error_message)."""
    text = (text or "").strip()
    if not text:
        return None, ("Paste a proxy link (vless://, vmess://, trojan://, ss://, hysteria2://, tuic://, "
                      "wireguard://) or a sing-box / Xray outbound JSON object first.")

    try:
        low = text.lower()
        if text.startswith("{"):
            try:
                node = json.loads(text)
            except ValueError:
                node = None
            ob = _parse_raw_xray(node) if isinstance(node, dict) and _looks_like_xray(node) else _parse_raw_json(text)
        elif low.startswith("vless://"):
            ob = _parse_vless(text)
        elif low.startswith("vmess://"):
            ob = _parse_vmess(text)
        elif low.startswith("trojan://"):
            ob = _parse_trojan(text)
        elif low.startswith("ss://"):
            ob = _parse_shadowsocks(text)
        elif low.startswith(("hysteria2://", "hy2://")):
            ob = _parse_hysteria2(text)
        elif low.startswith("tuic://"):
            ob = _parse_tuic(text)
        elif low.startswith(("wireguard://", "wg://")):
            ob = _parse_wireguard(text)
        else:
            return None, ("Unrecognized format. Expected vless://, vmess://, trojan://, ss://, hysteria2://, "
                          "tuic://, wireguard:// or a sing-box / Xray JSON object starting with '{'.")
        register_secrets(ob)
        return ob, None
    except ParseError as ex:
        return None, str(ex)
    except Exception as ex:
        return None, f"Could not parse the proxy configuration: {ex}"


# ============================================================================
# sing-box config builder
#
# Routes ONLY Discord.exe / DiscordPTB.exe / DiscordCanary.exe through the
# user's outbound; every other rule (and the route.final fallback) is
# "direct". There is no 0.0.0.0/0 -> proxy rule anywhere here, and the
# Windows system proxy / default gateway are never touched.
# ============================================================================

DISCORD_DOMAIN_SUFFIXES = [
    "discord.com",
    "discordapp.com",
    "discord.gg",
    "discordapp.net",
    "discord.media",
    "dis.gd",
    "discordcdn.com",
    "discordstatic.com",
    "discord.co",
    "discordsays.com",
    # File uploads: Discord PUTs attachments straight to Google Cloud Storage under this exact
    # hostname (not a discord* domain). Without it, uploads left direct in "Discord only" mode
    # and silently failed. Only this one hostname - the rest of googleapis.com is untouched.
    "discord-attachments-uploads-prd.storage.googleapis.com",
]


def _is_probe_flow(md: dict) -> bool:
    """The voice-quality probe's own UDP flow (never counted as Discord traffic or a voice call)."""
    return (str(md.get("destinationIP") or "") == PROBE_DEST[0]
            and str(md.get("destinationPort") or "") == str(PROBE_DEST[1]))


def singbox_clean(ob: dict) -> dict:
    """Drops our private \"_xxx\" helper keys, which sing-box would reject."""
    return {k: v for k, v in ob.items() if not k.startswith("_")}


def build_singbox_config(user_outbound: dict, api: dict | None = None, capture: dict | None = None) -> dict:
    cfg = _build_singbox_config_core(user_outbound, api, capture)
    return _wireguard_as_endpoint(cfg, user_outbound)


def _wireguard_as_endpoint(cfg: dict, user_outbound: dict) -> dict:
    """sing-box 1.11+ runs WireGuard as an *endpoint*, not an outbound; the tag stays the
    same so every route rule and the selector keep pointing at it."""
    if user_outbound.get("type") == "wireguard":
        cfg["outbounds"] = [o for o in cfg["outbounds"] if o.get("tag") != OUTBOUND_TAG]
        cfg["endpoints"] = [singbox_clean(user_outbound)]
    return cfg


def _build_singbox_config_core(user_outbound: dict, api: dict | None = None, capture: dict | None = None) -> dict:
    cfg = {
        "log": {"level": "info", "timestamp": True},
        "dns": {
            "servers": [
                # Everything that isn't Discord keeps resolving exactly as
                # before - through Windows' normal DNS path, untouched.
                {"type": "local", "tag": "direct-dns"},
                # Discord's domains get a placeholder ("fake") IP. Discord then
                # connects to that placeholder through the proxy, and the
                # proxy SERVER does the real lookup - so no poisoned local
                # answer is ever used and no extra DNS-over-proxy is needed.
                {"type": "fakeip", "tag": "fakeip", "inet4_range": "198.18.0.0/15"},
            ],
            "rules": [
                {"domain_suffix": DISCORD_DOMAIN_SUFFIXES, "server": "fakeip"}
            ],
            "final": "direct-dns",
            "strategy": "prefer_ipv4",
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": "DiscordProxy",
                "address": ["172.19.0.1/30"],
                "mtu": 1500,
                "auto_route": True,
                "strict_route": True,
                "stack": "mixed",
            }
        ],
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": [OUTBOUND_TAG]},
            singbox_clean(user_outbound),
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
        ],
        "route": {
            "auto_detect_interface": True,
            # Any outbound that dials a hostname (e.g. the user's proxy
            # server address) needs a resolver assigned to it now - point
            # it at the plain local/direct resolver, never remote-dns,
            # since remote-dns is only reachable *through* the proxy and
            # resolving the proxy's own address through itself would be
            # circular.
            "default_domain_resolver": {"server": "direct-dns"},
            # Belt-and-braces: anything matching no rule below still falls
            # through to direct, never to the proxy.
            "final": "direct",
            "rules": [
                # TUN captures every DNS packet system-wide (regardless of
                # which process sent it - Windows funnels DNS through its
                # own DNS Client service). Without this, those packets fall
                # through to the ordinary connection rules below as if they
                # were ordinary traffic, which newer sing-box rejects.
                # hijack-dns hands them to the dns{} block above instead,
                # which is what actually applies the Discord-domain ->
                # remote-resolver split.
                {"action": "sniff"},
                # ONLY hijack DNS that Discord actually depends on:
                #   - Discord's own processes (Chromium has its own resolver)
                #   - Windows' DNS Client service (svchost.exe / dnsrslvr.dll),
                #     which resolves names on behalf of Discord and most apps
                # Any OTHER program that does its own DNS (TeamSpeak, games,
                # torrent clients, VPN tools, ...) is left completely alone:
                # its DNS packets skip hijack-dns and go straight out the
                # normal connection below. This is why new programs keep
                # working without having to be listed one by one.
                {"protocol": "dns", "process_name": DISCORD_PROCESS_NAMES + ["svchost.exe"],
                 "action": "hijack-dns"},
                {"protocol": "dns", "process_path_regex": [r"(?i).*dnsrslvr\.dll.*"],
                 "action": "hijack-dns"},
                # Discord's Chromium tries HTTP/3 (QUIC, UDP 443) first for hostnames such as the
                # attachment-upload host. Many proxy servers carry UDP badly, so an upload filled
                # the progress bar and then silently failed. Rejecting QUIC to Discord's domains
                # makes it fall back to normal TCP/TLS at once. Voice is unaffected: it uses
                # literal IPs on other UDP ports, never a Discord hostname on UDP 443.
                {"network": "udp", "port": 443, "process_name": DISCORD_PROCESS_NAMES,
                 "domain_suffix": DISCORD_DOMAIN_SUFFIXES, "action": "reject"},
                {"process_name": DISCORD_PROCESS_NAMES, "outbound": "proxy"},
                # Never proxy private/LAN destinations (router, local PCs,
                # Steam/activation servers on the LAN, etc.).
                {
                    "ip_is_private": True,
                    "outbound": "direct",
                },
                # Only Discord processes select the proxy. Everything else
                # falls through to the direct outbound below.
                {"inbound": ["tun-in"], "outbound": "direct"},
            ],
        },
    }
    if capture:
        tun = cfg["inbounds"][0]
        # strict_route is the most invasive TUN option (it adds Windows firewall
        # rules and blocks DNS around the tunnel); callers can turn it off.
        tun["strict_route"] = bool(capture.get("strict_route", True))
        # Switchable in Settings (defaults = what it always used): the TUN stack and
        # MTU can change how UDP voice packets are paced through the tunnel.
        if capture.get("stack") in ("mixed", "system", "gvisor"):
            tun["stack"] = capture["stack"]
        if capture.get("mtu"):
            tun["mtu"] = int(capture["mtu"])
        # With route_address the TUN gets routes ONLY for these destinations
        # instead of taking over the default route, so other programs'
        # traffic (games, ...) never enters it.
        if capture.get("route_address"):
            tun["route_address"] = list(capture["route_address"])
        if capture.get("route_exclude_address"):
            tun["route_exclude_address"] = list(capture["route_exclude_address"])
    if api:
        # Local-only stats endpoint (127.0.0.1, random port + random secret),
        # polled by TrafficMonitor to show total upload/download.
        cfg["experimental"] = {"clash_api": {
            "external_controller": f"127.0.0.1:{api['port']}",
            "secret": api["secret"],
        }}
        if api.get("probe_port"):
            # Voice-quality probe: a loopback UDP inbound whose packets are sent through the SAME
            # outbound as Discord, re-addressed to PROBE_DEST (see VoiceQualityProbe). First rule.
            cfg["inbounds"].append({"type": "direct", "tag": PROBE_INBOUND_TAG, "listen": "127.0.0.1",
                                    "listen_port": int(api["probe_port"]), "network": "udp"})
            cfg["route"]["rules"].insert(0, {"inbound": [PROBE_INBOUND_TAG], "action": "route",
                                             "outbound": "proxy", "override_address": PROBE_DEST[0],
                                             "override_port": PROBE_DEST[1]})
    return cfg


# ============================================================================
# Discord process detection (no extra dependencies - shells out to tasklist)
# ============================================================================

_NO_WINDOW = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0


# ============================================================================
# Xray-core chaining (XHTTP only)
#
# Vanilla sing-box has no XHTTP support (its transport switch simply has no
# case for it - confirmed against sing-box's own source). Rather than fake
# it or silently downgrade to a different wire protocol (which just produces
# confusing 403s or connections that hang with zero bytes received - both
# documented sing-box/NekoBox bugs when people have tried), an XHTTP link
# gets handed to a local Xray-core instance instead, which supports XHTTP
# natively. sing-box still does everything it's actually needed for here -
# the TUN adapter and per-process routing, neither of which Xray-core can do
# on its own - and its "proxy" outbound simply becomes a plain SOCKS5
# pointed at 127.0.0.1, with Xray-core doing the actual XHTTP+TLS/Reality
# work behind it. Every other outbound type (ws/grpc/http/httpupgrade/tcp)
# still goes straight to sing-box exactly as before - this path is only
# ever used for transport=="xhttp".
# ============================================================================

def uses_xhttp(outbound: dict) -> bool:
    return (outbound.get("transport") or {}).get("type") == "xhttp"


def needs_xray(outbound: dict) -> bool:
    """Links sing-box cannot carry at all: XHTTP, mKCP, or a raw Xray JSON outbound."""
    return (outbound.get("type") == "xray-raw"
            or (outbound.get("transport") or {}).get("type") in ("xhttp", "kcp"))


def _free_local_port() -> int:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def xray_outbound_from_parsed(ob: dict) -> dict:
    """Converts our sing-box-shaped parsed outbound into an Xray-core
    outbound object (any transport: tcp/ws/grpc/httpupgrade/http/xhttp)."""
    if ob.get("_xray_outbound"):  # pasted Xray JSON: used exactly as written
        node = json.loads(json.dumps(ob["_xray_outbound"]))
        node["tag"] = "xray-out"
        return node
    protocol = ob.get("type")
    tls = ob.get("tls") or {}
    transport = ob.get("transport") or {}
    ttype = transport.get("type") or "tcp"

    if tls.get("reality"):
        security = "reality"
    elif tls.get("enabled"):
        security = "tls"
    else:
        security = "none"

    network = {"xhttp": "xhttp", "ws": "ws", "grpc": "grpc", "httpupgrade": "httpupgrade",
               "http": "h2", "tcp": "tcp", "kcp": "kcp"}.get(ttype)
    if network is None:
        raise ParseError(f'Transport "{ttype}" is not supported for Xray-core by this tool.')
    stream = {"network": network, "security": security}

    host = transport.get("host") or ""
    path = transport.get("path") or "/"
    if ttype == "xhttp":
        xhttp_settings = {"path": path, "mode": transport.get("mode") or "auto"}
        if host:
            xhttp_settings["host"] = host
        if transport.get("extra"):
            try:
                xhttp_settings["extra"] = json.loads(transport["extra"])
            except (TypeError, ValueError):
                pass
        stream["xhttpSettings"] = xhttp_settings
    elif ttype == "ws":
        ws_host = (transport.get("headers") or {}).get("Host", "")
        ws_path = path
        if transport.get("max_early_data"):
            ws_path += ("&" if "?" in ws_path else "?") + f"ed={transport['max_early_data']}"
        ws = {"path": ws_path}
        if ws_host:
            ws["host"] = ws_host
        stream["wsSettings"] = ws
    elif ttype == "httpupgrade":
        hu = {"path": path}
        if host:
            hu["host"] = host
        stream["httpupgradeSettings"] = hu
    elif ttype == "grpc":
        stream["grpcSettings"] = {"serviceName": transport.get("service_name", "")}
    elif ttype == "http":
        h2 = {"path": path}
        hosts = transport.get("host")
        if hosts:
            h2["host"] = hosts if isinstance(hosts, list) else [hosts]
        stream["httpSettings"] = h2
    elif ttype == "kcp":
        kcp = {"header": {"type": transport.get("header") or "none"}}
        if transport.get("seed"):
            kcp["seed"] = transport["seed"]
        stream["kcpSettings"] = kcp

    if security == "tls":
        tls_settings = {"serverName": tls.get("server_name", ""), "allowInsecure": bool(tls.get("insecure", False))}
        if tls.get("alpn"):
            tls_settings["alpn"] = tls["alpn"]
        fp = (tls.get("utls") or {}).get("fingerprint")
        if fp:
            tls_settings["fingerprint"] = fp
        if ob.get("_pcs"):
            tls_settings["pinnedPeerCertSha256"] = ",".join(ob["_pcs"])
        if ob.get("_vcn"):
            tls_settings["verifyPeerCertByName"] = ob["_vcn"]
        if ob.get("_insecure"):
            tls_settings["allowInsecure"] = True
        stream["tlsSettings"] = tls_settings
    elif security == "reality":
        reality = tls.get("reality") or {}
        reality_settings = {
            "serverName": tls.get("server_name", ""),
            "publicKey": reality.get("public_key", ""),
            "shortId": reality.get("short_id", ""),
            "fingerprint": (tls.get("utls") or {}).get("fingerprint") or "chrome",
        }
        if ob.get("_spx"):
            reality_settings["spiderX"] = ob["_spx"]
        if ob.get("_pqv"):
            reality_settings["mldsa65Verify"] = ob["_pqv"]
        stream["realitySettings"] = reality_settings

    if protocol == "vless":
        user = {"id": ob.get("uuid", ""), "encryption": ob.get("_encryption") or "none"}
        if ob.get("flow"):
            user["flow"] = ob["flow"]
        settings = {"vnext": [{"address": ob["server"], "port": ob["server_port"], "users": [user]}]}
    elif protocol == "vmess":
        user = {"id": ob.get("uuid", ""), "security": ob.get("security", "auto")}
        if ob.get("alter_id"):
            user["alterId"] = ob["alter_id"]
        settings = {"vnext": [{"address": ob["server"], "port": ob["server_port"], "users": [user]}]}
    elif protocol == "trojan":
        settings = {"servers": [{"address": ob["server"], "port": ob["server_port"], "password": ob.get("password", "")}]}
    elif protocol == "shadowsocks":
        settings = {"servers": [{"address": ob["server"], "port": ob["server_port"],
                                 "method": ob.get("method", ""), "password": ob.get("password", "")}]}
        stream = {"network": "tcp", "security": "none"}
    else:
        raise ParseError(f'Xray-core mode is not supported for "{protocol}" outbounds by this tool (only vless/vmess/trojan/shadowsocks).')

    return {"tag": "xray-out", "protocol": protocol, "settings": settings, "streamSettings": stream}


def build_xray_config(ob: dict, socks_port: int, loglevel: str = "warning") -> dict:
    return {
        "log": {"loglevel": loglevel},
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
            }
        ],
        "outbounds": [xray_outbound_from_parsed(ob), {"protocol": "freedom", "tag": "direct"}],
    }


def socks_chain_outbound(socks_port: int) -> dict:
    """What sing-box's "user-proxy" outbound becomes when chained through
    the local Xray-core instance above: a plain, unencrypted-at-this-hop
    SOCKS5 to 127.0.0.1 - Xray-core does the real XHTTP+TLS/Reality work."""
    return {"type": "socks", "tag": OUTBOUND_TAG, "server": "127.0.0.1", "server_port": socks_port, "version": "5"}


_PROC_API = None


def running_process_names() -> set:
    """Lower-case executable names of every running process.

    Uses the Toolhelp snapshot API - no subprocess - so it is cheap enough
    to call every few seconds from the GUI thread."""
    if os.name != "nt":
        return set()
    global _PROC_API
    try:
        from ctypes import wintypes
        if _PROC_API is None:
            class PROCESSENTRY32W(ctypes.Structure):
                _fields_ = [
                    ("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
                    ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", wintypes.DWORD), ("szExeFile", ctypes.c_wchar * 260),
                ]
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
            k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
            k32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
            k32.Process32FirstW.restype = wintypes.BOOL
            k32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
            k32.Process32NextW.restype = wintypes.BOOL
            k32.CloseHandle.argtypes = [wintypes.HANDLE]
            _PROC_API = (k32, PROCESSENTRY32W)
        k32, PE = _PROC_API
        snap = k32.CreateToolhelp32Snapshot(0x2, 0)  # TH32CS_SNAPPROCESS
        if snap in (None, 0, -1) or snap == ctypes.c_void_p(-1).value:
            return set()
        names = set()
        try:
            pe = PE()
            pe.dwSize = ctypes.sizeof(PE)
            ok = k32.Process32FirstW(snap, ctypes.byref(pe))
            while ok:
                names.add(pe.szExeFile.lower())
                ok = k32.Process32NextW(snap, ctypes.byref(pe))
        finally:
            k32.CloseHandle(snap)
        return names
    except Exception:
        return set()


def get_running_discord_variant():
    names = running_process_names()
    for name in DISCORD_PROCESS_NAMES:
        if name.lower() in names:
            return name
    return None


# ----------------------------------------------------------------------------
# Close Discord completely (every Discord process, as seen in Task Manager)
# ----------------------------------------------------------------------------

# Exact image names. Discord's updater (Update.exe) has a generic name, so it - and anything else
# living inside %LOCALAPPDATA%\Discord, \DiscordPTB, \DiscordCanary or \DiscordDevelopment - is
# matched by its install folder instead (see the script below). This tool's own process is never touched.
DISCORD_KILL_NAMES = ["Discord.exe", "DiscordPTB.exe", "DiscordCanary.exe", "DiscordDevelopment.exe",
                      "DiscordHookHelper.exe", "DiscordHookHelper64.exe", "DiscordHookHelper32.exe"]


def close_discord_processes():
    """Force-closes every Discord process (all the Discord.exe workers, the updater, overlay helpers).
    Repeats a few times in case the updater respawns something. Returns (closed, still_running)."""
    if os.name != "nt":
        return 0, 0
    names = ",".join(f"'{n}'" for n in DISCORD_KILL_NAMES)
    script = (
        "$me = " + str(os.getpid()) + "\n"
        "$names = @(" + names + ")\n"
        "$root = [regex]::Escape($env:LOCALAPPDATA)\n"
        "$pat = '^' + $root + '\\\\Discord(PTB|Canary|Development)?\\\\'\n"
        "function Get-D { Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {\n"
        "  $_.ProcessId -ne $me -and (($names -contains $_.Name) -or ($_.ExecutablePath -and ($_.ExecutablePath -match $pat))) } }\n"
        "$killed = 0\n"
        "for ($i = 0; $i -lt 4; $i++) {\n"
        "  $p = @(Get-D)\n"
        "  if ($p.Count -eq 0) { break }\n"
        "  foreach ($x in $p) { Stop-Process -Id $x.ProcessId -Force -ErrorAction SilentlyContinue; $killed++ }\n"
        "  Start-Sleep -Milliseconds 700\n"
        "}\n"
        "$left = @(Get-D).Count\n"
        "\"RESULT $killed $left\"\n"
    )
    try:
        out = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True, text=True, timeout=40, creationflags=_NO_WINDOW,
        ).stdout
        for line in reversed(out.splitlines()):
            m = re.match(r"\s*RESULT (\d+) (\d+)\s*$", line)
            if m:
                return int(m.group(1)), int(m.group(2))
    except Exception:
        pass
    # PowerShell unavailable / blocked: fall back to taskkill by image name (kills the whole tree)
    for n in DISCORD_KILL_NAMES:
        try:
            subprocess.run(["taskkill", "/F", "/T", "/IM", n], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=10, creationflags=_NO_WINDOW)
        except Exception:
            pass
    time.sleep(0.8)
    left = sum(1 for n in DISCORD_KILL_NAMES if n.lower() in running_process_names())
    return -1, left     # -1 = number closed is unknown (taskkill fallback)


# ----------------------------------------------------------------------------
# Kill switch: while the proxy is down, Windows Firewall blocks Discord's own
# outbound traffic so it can never fall back to your direct connection.
# ----------------------------------------------------------------------------

KILLSWITCH_RULE = "DiscordProxy KillSwitch"
_KS_LOCK = threading.Lock()


def _discord_program_paths() -> list:
    local = os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Local")
    found = set()
    for folder in ("Discord", "DiscordPTB", "DiscordCanary", "DiscordDevelopment"):
        root = os.path.join(local, folder)
        for pat in (os.path.join(root, "app-*", "*.exe"), os.path.join(root, "*.exe")):
            for p in glob.glob(pat):
                base = os.path.basename(p).lower()
                if base.startswith("discord") or base == "update.exe":
                    found.add(os.path.normpath(p))
    return sorted(found)


def _netsh_fw(args: list, timeout: int = 15):
    return subprocess.run(["netsh", "advfirewall", "firewall"] + args, capture_output=True, text=True,
                          timeout=timeout, creationflags=_NO_WINDOW)


def killswitch_release() -> None:
    """Removes every kill-switch firewall rule (Discord can reach the network again)."""
    if os.name != "nt":
        return
    try:
        _netsh_fw(["delete", "rule", f"name={KILLSWITCH_RULE}"])
    except Exception:
        pass


def killswitch_engage() -> int:
    """Adds an outbound BLOCK rule for every Discord program. Returns how many rules were added."""
    if os.name != "nt":
        return 0
    killswitch_release()                       # never stack duplicates
    added = 0
    for path in _discord_program_paths():
        try:
            r = _netsh_fw(["add", "rule", f"name={KILLSWITCH_RULE}", "dir=out", "action=block",
                           f"program={path}", "enable=yes", "profile=any"])
            if r.returncode == 0:
                added += 1
        except Exception:
            pass
    return added


def killswitch_rules_exist() -> bool:
    if os.name != "nt":
        return False
    try:
        r = _netsh_fw(["show", "rule", f"name={KILLSWITCH_RULE}"])
        return r.returncode == 0 and KILLSWITCH_RULE.lower() in (r.stdout or "").lower()
    except Exception:
        return False


# ----------------------------------------------------------------------------
# Test helpers: SSL environment repair + test through the LIVE proxy's stats API
# ----------------------------------------------------------------------------

def sanitize_ssl_environment() -> list:
    """A leftover environment variable that points at a file/folder that no longer exists makes
    Python's HTTPS fail with the cryptic  <urlopen error [Errno 2] No such file or directory>
    (SSL_CERT_FILE / SSL_CERT_DIR / REQUESTS_CA_BUNDLE / CURL_CA_BUNDLE, or SSLKEYLOGFILE whose
    folder is gone). Removes only the broken ones for this process; returns their names."""
    removed = []
    for var in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
        v = os.environ.get(var)
        if v and not os.path.isfile(v):
            os.environ.pop(var, None)
            removed.append(var)
    v = os.environ.get("SSL_CERT_DIR")
    if v and not any(os.path.isdir(part) for part in v.split(os.pathsep) if part):
        os.environ.pop("SSL_CERT_DIR", None)
        removed.append("SSL_CERT_DIR")
    v = os.environ.get("SSLKEYLOGFILE")
    if v:
        try:
            ok = os.path.isdir(os.path.dirname(os.path.abspath(v)))
        except Exception:
            ok = False
        if not ok:
            os.environ.pop("SSLKEYLOGFILE", None)
            removed.append("SSLKEYLOGFILE")
    return removed


_SSL_ENV_FIXED = sanitize_ssl_environment()


def make_ssl_context():
    """(context, verified). Never raises. Tries the normal verified context first, then one built
    straight from the Windows certificate store, and only as a last resort an unverified one
    (the Test Proxy button only needs to know whether the tunnel carries traffic)."""
    import ssl
    try:
        return ssl.create_default_context(), True
    except Exception:
        pass
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        loaded = 0
        if os.name == "nt":
            for store in ("ROOT", "CA"):
                try:
                    for cert, enc, trust in ssl.enum_certificates(store):
                        if enc == "x509_asn" and (trust is True or "1.3.6.1.5.5.7.3.1" in trust):
                            try:
                                ctx.load_verify_locations(cadata=cert)
                                loaded += 1
                            except Exception:
                                pass
                except Exception:
                    pass
        if loaded:
            return ctx, True
    except Exception:
        pass
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx, False


def ssl_diagnostics() -> list:
    """Log lines that show exactly which file Python's TLS setup is looking for."""
    lines = []
    try:
        import ssl
        vp = ssl.get_default_verify_paths()
        lines.append(f"ssl: cafile={vp.cafile!r} (exists: {bool(vp.cafile and os.path.isfile(vp.cafile))}), "
                     f"capath={vp.capath!r}")
    except Exception as ex:
        lines.append(f"ssl: could not read verify paths ({ex})")
    for var in ("SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "SSLKEYLOGFILE"):
        if os.environ.get(var):
            lines.append(f"env {var}={os.environ[var]!r}")
    if _SSL_ENV_FIXED:
        lines.append("ignored broken environment variables at startup: " + ", ".join(_SSL_ENV_FIXED))
    return lines


def api_delay_test(port: int, secret: str, url: str, timeout_ms: int = 10000):
    """Asks the RUNNING sing-box to fetch `url` through the proxy outbound (its own delay test).
    Opens one extra short connection through the live chain - nothing is restarted or reconfigured,
    and no second sing-box / xray process is needed. Returns (ok, delay_ms, error_text)."""
    import urllib.error
    import urllib.parse
    import urllib.request
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    api = (f"http://127.0.0.1:{port}/proxies/{urllib.parse.quote(OUTBOUND_TAG)}/delay"
           f"?url={urllib.parse.quote(url, safe='')}&timeout={int(timeout_ms)}")
    req = urllib.request.Request(api, headers={"Authorization": f"Bearer {secret}"})
    try:
        with opener.open(req, timeout=timeout_ms / 1000 + 5) as r:
            data = json.load(r)
        return True, int(data.get("delay", 0)), ""
    except urllib.error.HTTPError as ex:
        msg = ""
        try:
            msg = str(json.loads(ex.read().decode("utf-8", "replace")).get("message") or "")
        except Exception:
            pass
        return False, None, mask_secrets(msg or f"HTTP {ex.code}")
    except Exception as ex:
        return False, None, f"could not reach the running proxy's local stats API ({ex})"


# ============================================================================
# Prerequisites
# ============================================================================

def check_prerequisites():
    singbox_ok = os.path.isfile(singbox_exe_path())
    wintun_ok = os.path.isfile(wintun_dll_path())
    admin_ok = is_admin()
    return [
        {"name": "sing-box.exe", "ok": singbox_ok,
         "detail": "found" if singbox_ok else "missing"},
        {"name": "wintun.dll", "ok": wintun_ok,
         "detail": "found" if wintun_ok else "missing"},
        {"name": "Administrator", "ok": admin_ok,
         "detail": "yes" if admin_ok else "no"},
        {"name": "xray-core", "ok": True,  # never blocks on its own - see detail
         "detail": "found" if os.path.isfile(xray_exe_path()) else "not found (XHTTP only)"},
    ]


def flush_dns() -> None:
    """Drop cached fake IPs so Discord doesn't keep them after the proxy stops."""
    if os.name != "nt":
        return
    try:
        subprocess.run(["ipconfig", "/flushdns"], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=8, creationflags=_NO_WINDOW)
    except Exception:
        pass


def build_test_config(user_outbound: dict, port: int, bypass_tun: bool = False) -> dict:
    """Tiny config: local HTTP/SOCKS proxy -> user's outbound. No TUN, no admin.

    bypass_tun=True is used when the real proxy is already running: the test instance then
    binds its outgoing connection to the physical network adapter (auto_detect_interface), so
    it never goes through the live TUN adapter and cannot disturb the running connection."""
    route = {"final": OUTBOUND_TAG, "default_domain_resolver": {"server": "local-dns"}}
    if bypass_tun:
        route["auto_detect_interface"] = True
    return _wireguard_as_endpoint({
        "log": {"level": "info", "timestamp": True},
        "dns": {"servers": [{"type": "local", "tag": "local-dns"}]},
        "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": port}],
        "outbounds": [singbox_clean(user_outbound), {"type": "direct", "tag": "direct"}],
        "route": route,
    }, user_outbound)



# ============================================================================
# sing-box process wrapper
# ============================================================================

_TUN_STATE = {"used": False}      # True once this run has started the real (TUN) sing-box


def remove_discord_tun_adapter(force: bool = False) -> None:
    """Best-effort removal of the Windows TUN adapter left by sing-box.

    sing-box normally removes its TUN interface during a graceful shutdown. If it is force-killed or
    Windows delays device removal, the adapter is removed explicitly as a second step.
    Without force=True this does nothing unless this run actually started sing-box - spawning
    PowerShell (several seconds each on some PCs) for an adapter that cannot exist made closing slow."""
    if os.name != "nt" or not (force or _TUN_STATE["used"]):
        return

    ps = (
        '$a = Get-NetAdapter -Name "DiscordProxy" -ErrorAction SilentlyContinue; '
        'if (-not $a) { exit 0 }; '
        '$a | Disable-NetAdapter -Confirm:$false -ErrorAction SilentlyContinue; '
        '$a | Remove-NetAdapter -Confirm:$false -ErrorAction SilentlyContinue; '
        'if (Get-NetAdapter -Name "DiscordProxy" -ErrorAction SilentlyContinue) { exit 1 } else { exit 0 }'
    )
    for _ in range(3):
        try:
            res = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=12, creationflags=_NO_WINDOW)
            if res.returncode == 0:
                return
        except Exception:
            pass
        time.sleep(0.5)


class SingBoxManager:
    def __init__(self, on_log, on_exit, cleanup_adapter=True):
        """on_log(str) and on_exit(int) are called from a BACKGROUND thread -
        callers must marshal back to the GUI thread themselves (this app
        does that via a queue.Queue, see DiscordProxyApp)."""
        self._process: subprocess.Popen | None = None
        self._reader_thread: threading.Thread | None = None
        self.on_log = on_log
        self.on_exit = on_exit
        self.cleanup_adapter = cleanup_adapter

    @property
    def is_running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def start(self, config_path: str) -> None:
        if self.is_running:
            raise RuntimeError("sing-box is already running.")
        exe = singbox_exe_path()
        if not os.path.isfile(exe):
            raise FileNotFoundError("sing-box.exe was not found next to this script.")

        creationflags = 0
        if os.name == "nt":
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | _NO_WINDOW

        if self.cleanup_adapter:
            _TUN_STATE["used"] = True
        self._process = subprocess.Popen(
            [exe, "run", "-c", config_path],
            cwd=base_dir(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            creationflags=creationflags,
        )
        self._reader_thread = threading.Thread(target=self._read_output, daemon=True)
        self._reader_thread.start()

    def _read_output(self) -> None:
        proc = self._process
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                self.on_log(line.rstrip("\n"))
        except Exception:
            pass
        finally:
            # proc.stdout hitting EOF doesn't guarantee the process has been
            # reaped yet - poll() can still race and return None here, so
            # wait() (which blocks briefly until it truly exits) is used to
            # get the real exit code instead of always falling back to -1.
            try:
                code = proc.wait(timeout=5)
            except Exception:
                code = proc.poll()
            self.on_exit(code if code is not None else -1)

    def stop(self) -> None:
        proc = self._process

        # Even if our Popen handle is already gone, clean up any stale TUN
        # adapter from a previous crashed/force-killed sing-box instance.
        if proc is None:
            if self.cleanup_adapter:
                remove_discord_tun_adapter()
            return

        try:
            if proc.poll() is None:
                # Ask sing-box to shut down cleanly first so it can restore
                # routes and close the TUN device itself.
                if os.name == "nt":
                    try:
                        proc.send_signal(signal.CTRL_BREAK_EVENT)
                    except Exception:
                        pass
                else:
                    proc.terminate()

                try:
                    proc.wait(timeout=5)
                except Exception:
                    # If CTRL_BREAK did not work, terminate the exact process
                    # tree rather than leaving sing-box alive after the GUI
                    # closes.
                    if os.name == "nt":
                        try:
                            subprocess.run(
                                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                timeout=5,
                                creationflags=_NO_WINDOW,
                            )
                        except Exception:
                            pass
                    else:
                        try:
                            proc.kill()
                        except Exception:
                            pass

                    try:
                        proc.wait(timeout=5)
                    except Exception:
                        pass
        finally:
            self._process = None

            # Do this AFTER sing-box is definitely stopped. Removing the
            # adapter while sing-box is still alive can immediately recreate
            # or re-open the interface.
            if self.cleanup_adapter:
                remove_discord_tun_adapter()


class XrayManager:
    """Same shape as SingBoxManager (is_running / start / stop, on_log /
    on_exit called from a background thread) but for xray.exe - no TUN
    adapter, so no admin requirement and no adapter cleanup on stop. Only
    ever used as a local, loopback-only SOCKS5 relay for XHTTP links; see
    the "Xray-core chaining" section above for why it exists at all."""

    def __init__(self, on_log, on_exit):
        self._process: subprocess.Popen | None = None
        self._reader_thread: threading.Thread | None = None
        self.on_log = on_log
        self.on_exit = on_exit

    @property
    def is_running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def start(self, config_path: str) -> None:
        if self.is_running:
            raise RuntimeError("xray-core is already running.")
        exe = xray_exe_path()
        if not os.path.isfile(exe):
            raise FileNotFoundError("xray.exe was not found next to this script.")

        creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        self._process = subprocess.Popen(
            [exe, "run", "-c", config_path],
            cwd=base_dir(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            creationflags=creationflags,
        )
        self._reader_thread = threading.Thread(target=self._read_output, daemon=True)
        self._reader_thread.start()

    def _read_output(self) -> None:
        proc = self._process
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                self.on_log(line.rstrip("\n"))
        except Exception:
            pass
        finally:
            try:
                code = proc.wait(timeout=5)
            except Exception:
                code = proc.poll()
            self.on_exit(code if code is not None else -1)

    def stop(self) -> None:
        proc = self._process
        if proc is None or proc.poll() is not None:
            self._process = None
            return
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
                proc.wait(timeout=3)
            except Exception:
                pass
        finally:
            self._process = None


CORE_CHOICES = {
    "Auto (recommended)": "auto",
    "sing-box": "singbox",
    "Xray-core": "xray",
}


def choose_core(outbound: dict, core: str) -> str:
    """Returns \"xray\" or \"singbox\" - which core carries the proxy connection.
    (sing-box always stays in front for the TUN adapter + per-process routing.)"""
    if core == "singbox":
        if needs_xray(outbound):
            raise ParseError(
                "This link uses XHTTP / mKCP / a raw Xray JSON config, which sing-box cannot do.\n\n"
                "Choose \"Xray-core\" (or \"Auto\") as the proxy core."
            )
        return "singbox"
    if core == "xray":
        if outbound.get("type") not in ("vless", "vmess", "trojan", "shadowsocks", "xray-raw"):
            raise ParseError(
                f'Xray-core mode supports vless / vmess / trojan / shadowsocks links, not "{outbound.get("type")}".\n\n'
                "Choose \"sing-box\" (or \"Auto\") as the proxy core."
            )
        return "xray"
    return "xray" if needs_xray(outbound) else "singbox"  # auto


def start_xray_chain_if_needed(outbound: dict, on_log, core: str = "auto", loglevel: str = "warning",
                               port: int | None = None, config_path: str | None = None):
    """Picks the proxy core. If Xray-core is to carry the connection, writes
    an xray config, starts xray-core against it, and returns
    (effective_outbound, XrayManager). Otherwise returns (outbound, None)
    unchanged - sing-box handles the outbound itself."""
    chosen = choose_core(outbound, core)
    on_log(f"--- proxy core: {'Xray-core' if chosen == 'xray' else 'sing-box'} (selected: {core}) ---")
    if chosen != "xray":
        return outbound, None

    if not os.path.isfile(xray_exe_path()):
        raise FileNotFoundError(
            "Xray-core is needed for this connection but xray.exe was not found "
            "next to this script. Download an official release from "
            "https://github.com/XTLS/Xray-core/releases (Xray-windows-64.zip -> xray.exe), "
            "or choose \"sing-box\" as the proxy core if your link allows it."
        )

    port = port or _free_local_port()  # a fixed port lets xray be restarted without touching sing-box
    cfg_path = config_path or xray_config_path()   # tests pass their own file - never the live one
    xray_cfg = build_xray_config(outbound, port, loglevel)
    os.makedirs(config_dir(), exist_ok=True)
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(xray_cfg, f, indent=2)

    err = validate_xray_config(cfg_path)
    if err:
        raise RuntimeError("xray-core rejected the configuration (xray -test):\n\n" + mask_secrets(err)[:1500])
    on_log(f"--- starting xray-core on 127.0.0.1:{port} with {cfg_path} ---")
    mgr = XrayManager(on_log=lambda l: on_log("[xray-core] " + l), on_exit=lambda c: None)
    mgr.start(cfg_path)

    import time
    time.sleep(0.3)  # give the local SOCKS listener a moment to come up
    return socks_chain_outbound(port), mgr


class TrafficMonitor:
    """Polls sing-box's local stats endpoint once a second and keeps running
    totals of bytes uploaded/downloaded through the proxy outbound (i.e.
    Discord's traffic only - direct traffic is not counted)."""

    def __init__(self, port: int, secret: str, on_update, on_log=None):
        self.port, self.secret, self.on_update, self.on_log = port, secret, on_update, on_log
        self._meta: dict = {}      # connection id -> (label, first seen) for the flow summaries
        self._act: dict = {}       # connection id -> [up, down, time of last change, logged (up, down)]
        self.up = self.down = 0
        self._closed_up = self._closed_down = 0
        self._live: dict = {}
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._thread.start()

    def _poll_once(self):
        import urllib.request
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/connections",
            headers={"Authorization": f"Bearer {self.secret}"},
        )
        with opener.open(req, timeout=2) as r:
            data = json.load(r)
        seen = {}
        now = time.monotonic()
        for c in data.get("connections") or []:
            if OUTBOUND_TAG in (c.get("chains") or []) and not _is_probe_flow(c.get("metadata") or {}):
                cid = c.get("id")
                seen[cid] = (int(c.get("upload", 0)), int(c.get("download", 0)))
                if cid not in self._meta:
                    md = c.get("metadata") or {}
                    host = md.get("host") or md.get("destinationIP") or "?"
                    self._meta[cid] = (f"{str(md.get('network', '')).lower()} {host}:{md.get('destinationPort', '')}", now)
        # diagnostic: a big flow that stopped moving (finished, or stalled) - log where it stands once
        for cid, (u, d) in seen.items():
            a = self._act.setdefault(cid, [u, d, now, None])
            if (u, d) != (a[0], a[1]):
                a[0], a[1], a[2] = u, d, now
            elif u + d >= 100_000 and now - a[2] >= 3 and a[3] != (u, d) and self.on_log:
                a[3] = (u, d)
                try:
                    self.on_log(f"--- flow idle: {self._meta.get(cid, ('?',))[0]}  up {fmt_bytes(u)}  "
                                f"down {fmt_bytes(d)}  (no movement for {now - a[2]:.0f}s, still open) ---")
                except Exception:
                    pass
        # a connection that vanished has finished: bank its last-seen bytes
        for cid, (u, d) in self._live.items():
            if cid not in seen:
                self._closed_up += u
                self._closed_down += d
                label, t0 = self._meta.get(cid, ("?", now))
                if self.on_log and u + d >= 100_000:
                    # diagnostic: a big flow with almost nothing coming back = the server never answered
                    try:
                        self.on_log(f"--- flow closed: {label}  up {fmt_bytes(u)}  down {fmt_bytes(d)}  "
                                    f"after {now - t0:.0f}s ---")
                    except Exception:
                        pass
        for cid in [k for k in self._meta if k not in seen]:
            del self._meta[cid]
        for cid in [k for k in self._act if k not in seen]:
            del self._act[cid]
        self._live = seen
        self.up = self._closed_up + sum(u for u, _ in seen.values())
        self.down = self._closed_down + sum(d for _, d in seen.values())

    def _run(self):
        while not self._stop.wait(1.0):
            try:
                self._poll_once()
                self.on_update(self.up, self.down)
            except Exception:
                pass

    def stop(self):
        """Stops polling, takes one last reading, returns (up, down)."""
        self._stop.set()
        try:
            self._thread.join(timeout=2)
        except RuntimeError:
            pass
        try:
            self._poll_once()
        except Exception:
            pass
        self.on_update(self.up, self.down)
        return self.up, self.down


# ============================================================================
# Capture modes: "Everything" (default) vs "Discord destinations only"
#
# Everything  - the TUN takes over the default route; sing-box then decides per
#               process (Discord -> proxy, all else -> direct). Most reliable,
#               but every program's traffic (CS2 included) passes through the
#               TUN, so starting/stopping the proxy touches all of it.
# Discord only - the TUN gets routes ONLY for the destinations Discord uses, so
#               other programs' packets never enter it. Discord's *voice*
#               servers are plain IP addresses (not names) and change, so the
#               ranges are LEARNED from Discord's own connections (see
#               learn_range_from_log_line) and can be edited by hand.
# ============================================================================

FAKEIP_RANGE = "198.18.0.0/15"   # must match the fakeip server in build_singbox_config
LEARNED_MAX = 500                # cap on auto-learned ranges
LEARN_PREFIX = 16                # a voice server's /16 neighbourhood is learned (Discord's voice hosts sit in big
                                 # cloud blocks; /22 made almost every new server a miss -> adapter restarts)

_RANGES_TEMPLATE = (
    "# Extra destination ranges for \"Discord destinations only\" mode.\n"
    "# One CIDR per line, e.g.  203.0.113.0/24\n"
    "# A line starting with \"-\" is EXCLUDED from the tunnel, e.g.  -155.133.0.0/16\n"
    "# (use that to make sure a game's servers can never enter it).\n"
    "# Ranges Discord is seen using are learned automatically into\n"
    "# discord_ranges_learned.txt; THIS file is yours and is never overwritten.\n"
)


def manual_ranges_path() -> str:
    return os.path.join(config_dir(), "discord_ranges.txt")


def learned_ranges_path() -> str:
    return os.path.join(config_dir(), "discord_ranges_learned.txt")


def ensure_manual_ranges_file() -> str:
    path = manual_ranges_path()
    if not os.path.exists(path):
        os.makedirs(config_dir(), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(_RANGES_TEMPLATE)
    return path


def read_ranges_file(path: str):
    """Returns (include, exclude) lists of normalised CIDR strings."""
    include, exclude = [], []
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError:
        return include, exclude
    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        negative = line.startswith("-")
        try:
            net = str(ipaddress.ip_network(line.lstrip("-+").strip(), strict=False))
        except ValueError:
            continue
        (exclude if negative else include).append(net)
    return include, exclude


_LEARN_RE = re.compile(
    r"outbound/[a-z0-9]+\[user-proxy\]: outbound (?:packet )?connection to (\d{1,3}(?:\.\d{1,3}){3}):\d+")


def learn_range_from_log_line(line: str):
    """If this sing-box log line shows Discord (the only thing routed to the
    proxy) reaching a literal public IPv4 address - i.e. voice/UDP media -
    returns that address's /22 as a CIDR string, else None."""
    m = _LEARN_RE.search(line)
    if not m or m.group(1) == PROBE_DEST[0]:
        return None
    try:
        ip = ipaddress.ip_address(m.group(1))
    except ValueError:
        return None
    if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
            or ip.is_unspecified or ip in ipaddress.ip_network(FAKEIP_RANGE)):
        return None
    return str(ipaddress.ip_network(f"{ip}/{LEARN_PREFIX}", strict=False))


_VOICE_WS_RE = re.compile(
    r"outbound/[a-z0-9]+\[user-proxy\]: outbound connection to [^\s:]+\.discord\.media:\d+")


def udp_voice_flowing(port: int, secret: str):
    """Is a UDP flow to a literal public IPv4 address (Discord voice media)
    currently going through the proxy? True / False, or None when sing-box's
    local stats endpoint could not be read (then nothing is changed)."""
    import urllib.request
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/connections",
            headers={"Authorization": f"Bearer {secret}"},
        )
        with opener.open(req, timeout=2) as r:
            data = json.load(r)
    except Exception:
        return None
    fake = ipaddress.ip_network(FAKEIP_RANGE)
    for c in data.get("connections") or []:
        md = c.get("metadata") or {}
        if str(md.get("network", "")).lower() != "udp":
            continue
        if OUTBOUND_TAG not in (c.get("chains") or []) or _is_probe_flow(md):
            continue
        try:
            ip = ipaddress.ip_address(md.get("destinationIP") or "")
        except ValueError:
            continue
        if (ip.version != 4 or ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_unspecified or ip in fake):
            continue
        return True
    return False


_dns_cache = (0.0, [])


def get_system_dns_servers() -> list:
    """IPv4 DNS servers Windows is configured with. Needed in 'Discord only'
    mode so that Discord's DNS lookups still reach the TUN (the fake-IP trick
    depends on seeing them)."""
    global _dns_cache
    if os.name != "nt":
        return []
    now = time.monotonic()
    if _dns_cache[1] and now - _dns_cache[0] < 30:
        return list(_dns_cache[1])
    ps = ("Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
          "ForEach-Object { $_.ServerAddresses } | Sort-Object -Unique")
    try:
        out = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps],
            capture_output=True, text=True, timeout=12, creationflags=_NO_WINDOW,
        ).stdout
    except Exception:
        return []
    servers = []
    for line in out.splitlines():
        line = line.strip()
        try:
            ip = ipaddress.ip_address(line)
        except ValueError:
            continue
        if ip.version != 4 or ip.is_loopback or ip.is_unspecified or line.startswith("172.19.0."):
            continue
        if line not in servers:
            servers.append(line)
    _dns_cache = (now, servers)
    return servers


def compute_discord_capture(learned):
    """Returns (capture_dict, "") or (None, reason) when 'Discord only' mode
    can't be used safely right now (the caller then captures everything)."""
    manual_inc, manual_exc = read_ranges_file(manual_ranges_path())
    include = sorted(set(learned) | set(manual_inc))
    if not include:
        return None, "no Discord destination ranges are known yet"
    dns = get_system_dns_servers()
    if not dns:
        return None, "the system DNS servers could not be detected"
    routes = []
    for r in [FAKEIP_RANGE] + [f"{d}/32" for d in dns] + include:
        if r not in routes:
            routes.append(r)
    return {"route_address": routes, "route_exclude_address": manual_exc}, ""


# ============================================================================
# Icons (drawn in code - no image files needed)
# ============================================================================

_BLUE = (88, 101, 242)   # default / not connected
_ICON_COLORS = {"running": (237, 66, 69), "busy": (250, 166, 26), "stopped": _BLUE}  # red = connected
_icon_cache: dict = {}


def _in_letter_p(u: float, v: float) -> bool:
    """True if the point (u, v), both in 0..1, lies inside the letter P."""
    sx0, sx1, y0, y1 = 0.365, 0.465, 0.24, 0.76     # stem
    cy, ro, ri = 0.41, 0.17, 0.07                    # bowl (outer / inner radius)
    if sx0 <= u <= sx1 and y0 <= v <= y1:
        return True
    if sx1 <= u:
        d = math.hypot(u - sx1, v - cy)
        if ri <= d <= ro:
            return True
    if sx1 - 0.0001 >= u >= sx0 and (cy - ro <= v <= cy - ri or cy + ri <= v <= cy + ro):
        return True
    return False


def render_icon_pixels(size: int, state: str) -> bytes:
    """RGBA, top-down. A round icon with a white letter P. The background
    colour shows the state: blue = not connected (default), red = connected,
    orange = starting/retrying. Any other state ("plain") is the blue logo."""
    key = (size, state)
    if key in _icon_cache:
        return _icon_cache[key]
    base, white = _ICON_COLORS.get(state, _BLUE), (255, 255, 255)
    c = size / 2
    big_r = size * 0.47
    ss = 3
    out = bytearray()
    for y in range(size):
        for x in range(size):
            n = r = g = b = 0
            for sy in range(ss):
                for sx in range(ss):
                    fx, fy = x + (sx + 0.5) / ss, y + (sy + 0.5) / ss
                    if math.hypot(fx - c, fy - c) <= big_r:
                        col = white if _in_letter_p(fx / size, fy / size) else base
                        n += 1
                        r += col[0]
                        g += col[1]
                        b += col[2]
            if n:
                out += bytes((r // n, g // n, b // n, n * 255 // (ss * ss)))
            else:
                out += b"\x00\x00\x00\x00"
    _icon_cache[key] = bytes(out)
    return _icon_cache[key]


def png_bytes(size: int, rgba: bytes) -> bytes:
    raw = b"".join(b"\x00" + rgba[y * size * 4:(y + 1) * size * 4] for y in range(size))

    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw))
            + chunk(b"IEND", b""))


def icon_resource_bytes(size: int, rgba: bytes) -> bytes:
    """32-bit DIB in the layout CreateIconFromResourceEx expects."""
    mask_len = ((size + 31) // 32) * 4 * size
    header = struct.pack("<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0, size * size * 4 + mask_len, 0, 0, 0, 0)
    pixels = bytearray()
    for y in range(size - 1, -1, -1):  # DIBs are stored bottom-up, BGRA
        for x in range(size):
            i = (y * size + x) * 4
            pixels += bytes((rgba[i + 2], rgba[i + 1], rgba[i], rgba[i + 3]))
    return header + bytes(pixels) + bytes(mask_len)


# ============================================================================
# Theme
# ============================================================================

LIGHT_PALETTE = {"fg": "#1a1a1a", "muted": "#666666", "field": "#ffffff", "field_fg": "#111111",
                 "sel": "#cce4ff", "ok": "#2e7d32", "warn": "#b26a00"}
DARK_PALETTE = {"bg": "#1e1f22", "fg": "#e3e5e8", "muted": "#9a9ea6", "field": "#2b2d31",
                "field_fg": "#f2f3f5", "btn": "#3a3d44", "btn_hover": "#4a4e57", "border": "#3f4248",
                "sel": "#3b5bdb", "ok": "#57d38c", "warn": "#f0b232"}


def windows_prefers_dark() -> bool:
    if os.name != "nt":
        return False
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize") as k:
            return winreg.QueryValueEx(k, "AppsUseLightTheme")[0] == 0
    except Exception:
        return False


# ============================================================================
# Plain-language failure explanations
# ============================================================================

# (key, title, advice, substrings searched in the lower-cased relevant log lines)
_FAILURE_RULES = [
    ("adapter", "Windows is still releasing the network adapter",
     "Wait about 10 seconds and press Start again. If it keeps happening, restart Windows.",
     ("device is not ready for use", "open interface take too much time", "configure tun interface",
      "file already exists")),
    ("admin", "Administrator rights are missing",
     "Click \"Restart as Administrator\" - creating the network adapter needs elevation.",
     ("access is denied", "requires elevation", "required privilege is not held")),
    ("wintun", "wintun.dll is missing or blocked",
     "Put the official wintun.dll next to this script and check that your antivirus did not quarantine it.",
     ("wintun",)),
    ("clock", "The clock on this PC looks wrong",
     "Sync Windows time (Settings > Time & language > Date & time > Sync now) and check the time zone, "
     "then press Start again. Some protocols fail silently when the time is off.",
     ("certificate has expired or is not yet valid", "invalid request time", "time skew", "invalid timestamp",
      "not yet valid")),
    ("port", "A network port is blocked or already in use",
     "Close any other copy of this app or another VPN/proxy tool, or restart Windows. "
     "Make sure your firewall allows sing-box.exe and xray.exe.",
     ("address already in use", "only one usage of each socket address", "bind: ")),
    ("key", "The server rejected your credentials",
     "Check the UUID / password, public key, short ID and SNI in your link - copy the link again "
     "from your provider.",
     ("invalid user", "authentication failed", "invalid password", "reality verification failed",
      "processed invalid connection", "wrong password", "unauthorized", "invalid uuid", "bad request id",
      "invalid request user id")),
    ("dns", "The server's address could not be found",
     "Check the server name in your link for typos and that your internet connection works.",
     ("no such host",)),
    ("unreachable", "The proxy server can't be reached",
     "Check your internet connection, then the server address and port in your link and that the server is "
     "online. A firewall or your ISP may be blocking it.",
     ("connection refused", "i/o timeout", "no route to host", "network is unreachable",
      "host is unreachable", "context deadline exceeded", "timed out")),
    ("config", "The proxy link or generated config is not valid",
     "Paste the link again from your provider; if it keeps failing, try the other proxy core.",
     ("decode config", "unmarshal", "unknown field", "invalid config", "parse config")),
    ("closed", "The server closed the connection",
     "Usually a wrong UUID / path / SNI / Reality setting, or the server is blocking you. "
     "Check the link or try the other proxy core.",
     ("eof", "connection reset", "forcibly closed")),
]


_SHORT_FAIL = {
    "adapter": ("Adapter busy", "Wait 10 s, then Start."),
    "admin": ("Not Administrator", "Use Restart as Administrator."),
    "wintun": ("wintun.dll missing", "Put it next to the script."),
    "clock": ("PC clock is wrong", "Sync Windows time."),
    "port": ("Port blocked or in use", "Close other VPN/proxy tools."),
    "key": ("Credentials rejected", "Check the link."),
    "dns": ("Server address not found", "Check the link."),
    "unreachable": ("Server unreachable", "Check link and internet."),
    "config": ("Invalid proxy config", "Paste the link again."),
    "closed": ("Server closed connection", "Check link or try other core."),
}
_SHORT_REASON = {t: _SHORT_FAIL[k][0] for k, t, _a, _n in _FAILURE_RULES if k in _SHORT_FAIL}
_SHORT_REASON.update({
    "sing-box stopped unexpectedly": "sing-box stopped",
    "xray-core stopped unexpectedly": "xray-core stopped",
    "The proxy server has not answered for several minutes": "No answer from server",
    "The proxy settings could not be applied": "Settings not applied",
})


def short_reason(reason: str) -> str:
    return _SHORT_REASON.get(reason, reason)


def explain_failure(lines):
    """Returns (key, title, advice) for the first known failure pattern found
    in the given log lines, or None. Only lines about the proxy/start-up are
    considered, so errors from ordinary direct connections don't confuse it."""
    relevant = []
    for ln in lines:
        low = ln.lower()
        if ("fatal" in low or "start service" in low or "[xray-core]" in low
                or "user-proxy" in low or "configure tun" in low or "wintun" in low
                or "open interface" in low):
            relevant.append(low)
    text = "\n".join(relevant)
    if not text:
        return None
    for key, title, advice, needles in _FAILURE_RULES:
        if any(n in text for n in needles):
            return key, title, advice
    return None


# ============================================================================
# Leftover cleanup (crashed / force-killed previous run)
# ============================================================================

def cleanup_leftovers() -> list:
    """Removes what a crashed previous run can leave behind: sing-box.exe /
    xray.exe processes started from THIS folder (other copies elsewhere are
    never touched) and a stale 'DiscordProxy' network adapter. Returns a list
    of human-readable descriptions of what was found."""
    if os.name != "nt":
        return []
    base = (base_dir().rstrip("\\") + "\\").replace("'", "''")
    script = (
        "$base = '" + base + "'\n"
        "foreach ($n in 'sing-box.exe','xray.exe') {\n"
        "  Get-CimInstance Win32_Process -Filter \"Name='$n'\" -ErrorAction SilentlyContinue |\n"
        "    Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($base, "
        "[StringComparison]::OrdinalIgnoreCase) } |\n"
        "    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue; \"process:$n\" }\n"
        "}\n"
        "if (Get-NetAdapter -Name 'DiscordProxy' -ErrorAction SilentlyContinue) { 'adapter' }\n"
    )
    found = []
    try:
        out = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True, text=True, timeout=30, creationflags=_NO_WINDOW,
        ).stdout
    except Exception:
        return found
    had_adapter = False
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("process:"):
            found.append(f"a leftover {line[8:]} process from a previous run")
        elif line == "adapter":
            had_adapter = True
            found.append("a stale network adapter")
    if had_adapter:
        remove_discord_tun_adapter(force=True)
    if found:
        flush_dns()
    return found


# ============================================================================
# Single instance
# ============================================================================

class SingleInstance:
    """Named mutex + named event. The first copy owns the mutex and waits on
    the event; a second copy sets the event (=> 'show your window') and exits."""

    MUTEX = "Local\\DiscordProxyGUI.SingleInstance"
    EVENT = "Local\\DiscordProxyGUI.ShowWindow"

    def __init__(self):
        self._mutex = None
        self._event = None
        self._thread = None
        self._stop = threading.Event()
        self._k32 = None
        self.signalled = False

    def _api(self):
        if self._k32 is None:
            from ctypes import wintypes
            k = ctypes.WinDLL("kernel32", use_last_error=True)
            k.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
            k.CreateMutexW.restype = wintypes.HANDLE
            k.CreateEventW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
            k.CreateEventW.restype = wintypes.HANDLE
            k.OpenEventW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
            k.OpenEventW.restype = wintypes.HANDLE
            k.SetEvent.argtypes = [wintypes.HANDLE]
            k.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
            k.WaitForSingleObject.restype = wintypes.DWORD
            k.CloseHandle.argtypes = [wintypes.HANDLE]
            self._k32 = k
        return self._k32

    def acquire(self) -> bool:
        """True = we are the only copy. False = another copy is running (it
        was asked to show its window if that was possible)."""
        if os.name != "nt":
            return True
        k = self._api()
        h = k.CreateMutexW(None, False, self.MUTEX)
        err = ctypes.get_last_error()
        if not h:
            return False  # e.g. access denied: an elevated copy owns it
        if err == 183:  # ERROR_ALREADY_EXISTS
            ev = k.OpenEventW(0x0002, False, self.EVENT)  # EVENT_MODIFY_STATE
            if ev:
                self.signalled = bool(k.SetEvent(ev))
                k.CloseHandle(ev)
            k.CloseHandle(h)
            return False
        self._mutex = h
        self._event = k.CreateEventW(None, False, False, self.EVENT)
        return True

    def listen(self, on_show) -> None:
        if os.name != "nt" or not self._event or self._thread:
            return
        self._stop.clear()
        k, ev = self._api(), self._event

        def loop():
            while not self._stop.is_set():
                if k.WaitForSingleObject(ev, 500) == 0:
                    try:
                        on_show()
                    except Exception:
                        pass

        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()

    def release(self) -> None:
        if os.name != "nt" or not self._k32:
            return
        self._stop.set()
        t, self._thread = self._thread, None
        if t:
            t.join(1.5)
        for attr in ("_event", "_mutex"):
            h = getattr(self, attr)
            if h:
                self._k32.CloseHandle(h)
                setattr(self, attr, None)


# ============================================================================
# Pre-flight: core versions + config validation (sing-box check / xray -test)
# ============================================================================

_VERSION_RE = re.compile(r"\b(\d+)\.(\d+)\.(\d+)\b")
_VERSION_CACHE: dict = {}

# APPROXIMATE first Xray-core release that understands each feature. These only
# produce a warning (never block the start) - raise/lower them as needed.
XRAY_FEATURES = (
    ("mlkem768x25519plus", (25, 5, 16), "VLESS ML-KEM encryption (encryption=mlkem768x25519plus...)"),
    ("pinnedPeerCertSha256", (25, 9, 5), "pinned certificate (pcs=)"),
    ("verifyPeerCertByName", (25, 9, 5), "verifyPeerCertByName (vcn=)"),
    ("xhttpSettings", (24, 11, 30), "XHTTP transport"),
)
SINGBOX_MIN = (1, 12, 0)  # typed DNS servers + route.default_domain_resolver used by the generated config


def _fmt_ver(v) -> str:
    return ".".join(str(x) for x in v)


def _run_tool(args, timeout: int = 20):
    try:
        r = subprocess.run(args, cwd=base_dir(), capture_output=True, text=True, timeout=timeout,
                           creationflags=_NO_WINDOW, encoding="utf-8", errors="replace")
        return r.returncode, ((r.stdout or "") + (r.stderr or "")).strip()
    except subprocess.TimeoutExpired:
        return None, f"timed out after {timeout}s"
    except OSError as ex:
        return None, str(ex)


def core_version(exe: str, arg_sets):
    """(major, minor, patch) read from `<exe> version`, cached per exe file; None if unreadable."""
    try:
        key = (exe, os.path.getmtime(exe))
    except OSError:
        return None
    if key not in _VERSION_CACHE:
        ver = None
        for args in arg_sets:
            _code, out = _run_tool([exe] + list(args), 8)
            m = _VERSION_RE.search(out or "")
            if m:
                ver = tuple(int(x) for x in m.groups())
                break
        _VERSION_CACHE[key] = ver
    return _VERSION_CACHE[key]


def preflight_info(outbound: dict):
    """Returns (info_line, [warnings]) about the installed cores vs. what this link needs."""
    warns, parts = [], []
    sb_exe = singbox_exe_path()
    if os.path.isfile(sb_exe):
        sb = core_version(sb_exe, (["version"],))
        parts.append("sing-box " + (_fmt_ver(sb) if sb else "?"))
        if sb is None:
            warns.append("could not read the sing-box version (`sing-box.exe version` gave no number)")
        elif sb < SINGBOX_MIN:
            warns.append(f"sing-box {_fmt_ver(sb)} is older than {_fmt_ver(SINGBOX_MIN)} - the generated "
                         "config needs 1.12 or newer; update sing-box.exe")
    if needs_xray(outbound) and os.path.isfile(xray_exe_path()):
        xv = core_version(xray_exe_path(), (["version"], ["-version"]))
        parts.append("xray-core " + (_fmt_ver(xv) if xv else "?"))
        try:
            blob = json.dumps(xray_outbound_from_parsed(outbound))
        except ParseError:
            blob = ""
        if xv is None:
            warns.append("could not read the xray-core version (`xray.exe version` gave no number)")
        else:
            for needle, minv, label in XRAY_FEATURES:
                if needle in blob and xv < minv:
                    warns.append(f"xray-core {_fmt_ver(xv)} is probably too old for {label} "
                                 f"(needs about {_fmt_ver(minv)}+) - update xray.exe")
            if '"allowInsecure": true' in blob:
                warns.append("this link disables certificate checking (allowInsecure); recent Xray builds "
                             "deprecate that - if TLS fails, use a pinned certificate (pcs=) instead")
    return ("cores: " + ", ".join(parts)) if parts else "", warns


def validate_singbox_config(path: str):
    """None when `sing-box check` accepts the file, else its exact error text."""
    exe = singbox_exe_path()
    if not os.path.isfile(exe):
        return None
    code, out = _run_tool([exe, "check", "-c", path], 20)
    if code == 0:
        return None
    return out or f"sing-box check failed (exit code {code})"


def validate_xray_config(path: str):
    """None when `xray run -test` accepts the file, else its exact error text."""
    exe = xray_exe_path()
    if not os.path.isfile(exe):
        return None
    code, out = _run_tool([exe, "run", "-test", "-c", path], 20)
    if code != 0 and re.search(r"flag provided but not defined|unknown (?:flag|command)|usage:", out or "", re.I):
        code, out = _run_tool([exe, "-test", "-c", path], 20)  # older Xray CLI
    if code == 0:
        return None
    return out or f"xray test failed (exit code {code})"


# ============================================================================
# Voice stall watchdog (Discord call stuck at ~5000 ms although the link is fine)
# ============================================================================

class VoiceStatus:
    """Shared state: written by the VoiceStallWatchdog thread, read by the window
    (live voice line) and by the mid-call guard."""

    IN_CALL_GRACE_S = 10.0

    def __init__(self):
        self.state = "idle"        # idle | ok | stalled | recovering
        self.up_bps = 0.0
        self.down_bps = 0.0
        self.resets = 0            # proxy-side voice flows reset by the watchdog this session
        self.last_flow_seen = 0.0  # monotonic time a voice UDP flow last existed
        self.flow = ""             # "ip:port" of the active voice flow

    def in_call(self) -> bool:
        return bool(self.last_flow_seen) and time.monotonic() - self.last_flow_seen < self.IN_CALL_GRACE_S


class VoiceStallWatchdog:
    """Watches the UDP flows to Discord voice servers through sing-box's local
    API. When a flow keeps SENDING but has received nothing for STALL_S seconds,
    its proxy-side session is dead (xray restarted, XHTTP stream dropped...) even
    though Discord's own socket is fine. Closing that one flow makes sing-box
    open a fresh session on Discord's very next packet - same local socket, no
    TUN rebuild, no need to leave and rejoin the voice channel.

    It also keeps `status` (idle / ok / stalled / recovering, up/down rate, reset
    count) up to date and reports it through `on_status` for the window."""

    STALL_S = 6.0        # sending but receiving nothing for this long = reset the flow
    SHOW_STALL_S = 3.0   # ... and the window already shows "stalled" after this long
    RECOVER_WAIT_S = 20.0  # after a reset, how long to wait for traffic to come back
    COOLDOWN_S = 15.0    # never reset the same flow more often than this
    POLL_S = 2.0

    def __init__(self, port: int, secret: str, on_log, status: "VoiceStatus | None" = None, on_status=None):
        self.port, self.secret, self.on_log = port, secret, on_log
        self.status = status or VoiceStatus()
        self.on_status = on_status
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._state: dict = {}   # id -> [last_down, last_up, last_progress_time, last_reset_time]
        self._recovering_since = 0.0
        self._last_poll = 0.0

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _api(self, method: str, path: str):
        import urllib.request
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", method=method,
                                     headers={"Authorization": f"Bearer {self.secret}"})
        with opener.open(req, timeout=3) as r:
            body = r.read()
        return json.loads(body) if body and method == "GET" else None

    @staticmethod
    def _is_voice_udp(c: dict, fake) -> bool:
        md = c.get("metadata") or {}
        if str(md.get("network", "")).lower() != "udp" or OUTBOUND_TAG not in (c.get("chains") or []):
            return False
        if _is_probe_flow(md):
            return False
        try:
            ip = ipaddress.ip_address(md.get("destinationIP") or "")
        except ValueError:
            return False
        return not (ip.version != 4 or ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_multicast or ip.is_unspecified or ip in fake)

    def _run(self):
        fake = ipaddress.ip_network(FAKEIP_RANGE)
        while not self._stop.wait(self.POLL_S):
            try:
                data = self._api("GET", "/connections") or {}
            except Exception:
                continue
            now = time.monotonic()
            dt = (now - self._last_poll) if self._last_poll else self.POLL_S
            self._last_poll = now
            dt = max(dt, 0.5)
            live, flows, stalled = set(), 0, False
            flow_label = ""
            d_up = d_down = 0
            for c in data.get("connections") or []:
                if not self._is_voice_udp(c, fake):
                    continue
                flows += 1
                if not flow_label:
                    _m = c.get("metadata") or {}
                    flow_label = f"{_m.get('destinationIP')}:{_m.get('destinationPort')}"
                cid = c.get("id")
                up, down = int(c.get("upload") or 0), int(c.get("download") or 0)
                live.add(cid)
                fresh = cid not in self._state
                st = self._state.setdefault(cid, [down, up, now, 0.0])
                if not fresh:
                    d_up += max(0, up - st[1])
                    d_down += max(0, down - st[0])
                if down > st[0] or up == st[1]:      # receiving, or we are not sending (muted/idle)
                    st[2] = now
                st[0], st[1] = down, up
                if now - st[2] >= self.SHOW_STALL_S:
                    stalled = True
                if now - st[2] >= self.STALL_S and now - st[3] >= self.COOLDOWN_S:
                    st[3], st[2] = now, now
                    md = c.get("metadata") or {}
                    try:
                        self._api("DELETE", f"/connections/{cid}")
                        self.status.resets += 1
                        self._recovering_since = now
                        stalled = False
                        self.on_log(f"--- voice watchdog: UDP flow to {md.get('destinationIP')}:{md.get('destinationPort')} "
                                    f"was sending but receiving nothing for {int(self.STALL_S)}s - flow reset, "
                                    f"Discord's next packet opens a fresh session (no rejoin needed) ---")
                    except Exception:
                        pass
            for cid in [k for k in self._state if k not in live]:
                del self._state[cid]

            if flows:
                self.status.last_flow_seen = now
            self.status.flow = flow_label
            recovering = bool(self._recovering_since) and now - self._recovering_since < self.RECOVER_WAIT_S
            if self._recovering_since and recovering and d_down > 0:
                self._recovering_since, recovering = 0.0, False
                self.on_log("--- voice watchdog: voice traffic is flowing both ways again ---")
            elif self._recovering_since and not recovering:
                self._recovering_since = 0.0           # stopped waiting; a new stall resets again
            if recovering:
                state = "recovering"
            elif not flows:
                state = "idle"
            elif stalled:
                state = "stalled"
            else:
                state = "ok"
            self.status.state = state
            self.status.up_bps, self.status.down_bps = d_up / dt, d_down / dt
            if self.on_status:
                try:
                    self.on_status((state, self.status.up_bps, self.status.down_bps, self.status.resets))
                except Exception:
                    pass


# ============================================================================
# Health check (is the proxy SERVER still answering?)
# ============================================================================

class HealthMonitor:
    """Every `interval` seconds measures the proxy through sing-box's local API:
    up to SAMPLES delay tests against Discord's own gateway (the real path),
    then the MEDIAN of the successful ones. One slow or lost sample does not
    count as a failure - a majority of the samples has to fail. If Discord's
    gateway does not answer at all, a neutral control URL decides whether the
    proxy itself is dead or only Discord is unreachable.

    on_result gets a dict: {"verdict": "ok" | "fail" | "unsupported",
    "median": ms | None, "note": str}. ('down' = the local API itself is gone;
    the process watcher handles that, so nothing is reported.)"""

    GATEWAY_URL = "https://discord.com/api/v9/gateway"
    CONTROL_URL = "http://cp.cloudflare.com/generate_204"
    SAMPLES = 3
    SAMPLE_GAP_S = 1.0
    SAMPLE_TIMEOUT_MS = 5000

    def __init__(self, port: int, secret: str, on_result, interval: float = 20.0, first_delay: float = 10.0):
        self.port, self.secret, self.on_result = port, secret, on_result
        self.interval, self.first_delay = interval, first_delay
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _delay(self, url: str):
        """One delay test through the proxy outbound -> ('ok', ms) | ('fail', None) |
        ('unsupported', None) | ('down', None)."""
        import urllib.error
        import urllib.parse
        import urllib.request
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        api = (f"http://127.0.0.1:{self.port}/proxies/{urllib.parse.quote(OUTBOUND_TAG)}/delay"
               f"?url={urllib.parse.quote(url, safe='')}&timeout={self.SAMPLE_TIMEOUT_MS}")
        req = urllib.request.Request(api, headers={"Authorization": f"Bearer {self.secret}"})
        try:
            with opener.open(req, timeout=self.SAMPLE_TIMEOUT_MS / 1000 + 4) as r:
                data = json.load(r)
            return "ok", int(data.get("delay", 0))
        except urllib.error.HTTPError as ex:
            return ("unsupported", None) if ex.code in (404, 405) else ("fail", None)
        except Exception:
            return "down", None

    def probe(self) -> dict:
        import statistics
        ok_ms, fails = [], 0
        for i in range(self.SAMPLES):
            if self._stop.is_set():
                break
            kind, ms = self._delay(self.GATEWAY_URL)
            if kind in ("down", "unsupported"):
                return {"verdict": kind, "median": None, "note": ""}
            if kind == "ok":
                ok_ms.append(ms)
            else:
                fails += 1
            if len(ok_ms) >= 2 or fails >= 2:          # a majority is already decided
                break
            if i < self.SAMPLES - 1 and self._stop.wait(self.SAMPLE_GAP_S):
                break
        if ok_ms and len(ok_ms) > fails:
            return {"verdict": "ok", "median": int(statistics.median(ok_ms)), "note": ""}
        kind, ms = self._delay(self.CONTROL_URL)
        if kind == "ok":
            return {"verdict": "ok", "median": ms,
                    "note": "Discord's gateway did not answer through the proxy, but the proxy itself works"}
        if kind in ("down", "unsupported"):
            return {"verdict": kind, "median": None, "note": ""}
        return {"verdict": "fail", "median": None, "note": ""}

    def _run(self):
        if self._stop.wait(self.first_delay):
            return
        while not self._stop.is_set():
            try:
                result = self.probe()
            except Exception:
                result = {"verdict": "down", "median": None, "note": ""}
            if self._stop.is_set():
                return
            if result["verdict"] != "down":
                try:
                    self.on_result(result)
                except Exception:
                    pass
            if result["verdict"] == "unsupported":
                return
            if self._stop.wait(self.interval):
                return


# ============================================================================
# System tray icon (pure ctypes - no extra packages needed)
# ============================================================================

class TrayIcon:
    """A Windows notification-area icon built on Shell_NotifyIconW.

    Lives for the whole session (so status + balloon notifications work even
    while the window is visible). Runs its own hidden window and message loop
    in a background thread.
      - left click / double click -> on_show()
      - right click               -> Show / Start / Stop / Exit completely
    Callbacks run on the tray thread, so they only hand work to the GUI
    thread (the app does that through its event queue).
    """

    _counter = 0

    def __init__(self, on_show, on_exit, on_start, on_stop):
        self._cb = {"show": on_show, "exit": on_exit, "start": on_start, "stop": on_stop}
        self._hwnd = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._user32 = None
        self._lock = threading.Lock()
        self._state = "stopped"        # stopped | starting | running | retrying
        self._icon_state = "stopped"   # stopped | running | busy
        self._tooltip = "Discord Proxy"
        self._modify = None

    @property
    def active(self) -> bool:
        return self._hwnd is not None

    def start(self) -> bool:
        """Creates the tray icon. Returns True if it is really there."""
        if self.active:
            return True
        self._ready.clear()
        self._thread = threading.Thread(target=self._run_guarded, daemon=True)
        self._thread.start()
        self._ready.wait(3.0)
        return self.active

    def stop(self) -> None:
        hwnd, user32, t = self._hwnd, self._user32, self._thread
        if hwnd and user32:
            try:
                user32.PostMessageW(hwnd, 0x0010, 0, 0)  # WM_CLOSE
            except Exception:
                pass
        if t and t is not threading.current_thread():
            t.join(2.0)
        self._thread = None

    def set_state(self, state: str, icon_state: str, tooltip: str) -> None:
        self._state, self._icon_state, self._tooltip = state, icon_state, tooltip
        if self._modify:
            try:
                self._modify(None)
            except Exception:
                pass

    def notify(self, title: str, text: str, kind: str = "info") -> None:
        if self._modify:
            try:
                self._modify((title, text, kind))
            except Exception:
                pass

    def _run_guarded(self) -> None:
        try:
            self._run()
        except Exception:
            pass
        finally:
            self._modify = None
            self._hwnd = None
            self._ready.set()

    def _run(self) -> None:
        from ctypes import wintypes

        user32 = ctypes.WinDLL("user32", use_last_error=True)
        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._user32 = user32

        LRESULT = ctypes.c_ssize_t
        WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wintypes.HWND, wintypes.UINT,
                                     wintypes.WPARAM, wintypes.LPARAM)

        class WNDCLASSW(ctypes.Structure):
            _fields_ = [
                ("style", wintypes.UINT), ("lpfnWndProc", WNDPROC),
                ("cbClsExtra", ctypes.c_int), ("cbWndExtra", ctypes.c_int),
                ("hInstance", wintypes.HINSTANCE), ("hIcon", wintypes.HANDLE),
                ("hCursor", wintypes.HANDLE), ("hbrBackground", wintypes.HANDLE),
                ("lpszMenuName", wintypes.LPCWSTR), ("lpszClassName", wintypes.LPCWSTR),
            ]

        class GUID(ctypes.Structure):
            _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                        ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]

        class NOTIFYICONDATAW(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.DWORD), ("hWnd", wintypes.HWND),
                ("uID", wintypes.UINT), ("uFlags", wintypes.UINT),
                ("uCallbackMessage", wintypes.UINT), ("hIcon", wintypes.HANDLE),
                ("szTip", ctypes.c_wchar * 128), ("dwState", wintypes.DWORD),
                ("dwStateMask", wintypes.DWORD), ("szInfo", ctypes.c_wchar * 256),
                ("uTimeoutOrVersion", wintypes.UINT), ("szInfoTitle", ctypes.c_wchar * 64),
                ("dwInfoFlags", wintypes.DWORD), ("guidItem", GUID),
                ("hBalloonIcon", wintypes.HANDLE),
            ]

        # 64-bit safe prototypes (handles are 64-bit; ctypes defaults to 32-bit int)
        user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        user32.DefWindowProcW.restype = LRESULT
        user32.RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASSW)]
        user32.RegisterClassW.restype = wintypes.ATOM
        user32.UnregisterClassW.argtypes = [wintypes.LPCWSTR, wintypes.HINSTANCE]
        user32.CreateWindowExW.argtypes = [
            wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
            ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
            wintypes.HWND, wintypes.HANDLE, wintypes.HINSTANCE, ctypes.c_void_p]
        user32.CreateWindowExW.restype = wintypes.HWND
        user32.DestroyWindow.argtypes = [wintypes.HWND]
        user32.PostQuitMessage.argtypes = [ctypes.c_int]
        user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        user32.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
        user32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
        user32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
        user32.LoadIconW.argtypes = [wintypes.HINSTANCE, ctypes.c_void_p]
        user32.LoadIconW.restype = wintypes.HANDLE
        user32.CreateIconFromResourceEx.argtypes = [ctypes.c_char_p, wintypes.DWORD, wintypes.BOOL,
                                                    wintypes.DWORD, ctypes.c_int, ctypes.c_int, wintypes.UINT]
        user32.CreateIconFromResourceEx.restype = wintypes.HANDLE
        user32.DestroyIcon.argtypes = [wintypes.HANDLE]
        user32.CreatePopupMenu.restype = wintypes.HANDLE
        user32.AppendMenuW.argtypes = [wintypes.HANDLE, wintypes.UINT, ctypes.c_size_t, wintypes.LPCWSTR]
        user32.TrackPopupMenu.argtypes = [wintypes.HANDLE, wintypes.UINT, ctypes.c_int, ctypes.c_int,
                                          ctypes.c_int, wintypes.HWND, ctypes.c_void_p]
        user32.DestroyMenu.argtypes = [wintypes.HANDLE]
        user32.GetCursorPos.argtypes = [ctypes.POINTER(wintypes.POINT)]
        user32.SetForegroundWindow.argtypes = [wintypes.HWND]
        user32.RegisterWindowMessageW.argtypes = [wintypes.LPCWSTR]
        user32.RegisterWindowMessageW.restype = wintypes.UINT
        shell32.Shell_NotifyIconW.argtypes = [wintypes.DWORD, ctypes.POINTER(NOTIFYICONDATAW)]
        kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        kernel32.GetModuleHandleW.restype = wintypes.HINSTANCE

        WM_TRAY = 0x8001            # WM_APP + 1
        WM_DESTROY, WM_CLOSE = 0x0002, 0x0010
        WM_LBUTTONUP, WM_LBUTTONDBLCLK, WM_RBUTTONUP, WM_CONTEXTMENU = 0x0202, 0x0203, 0x0205, 0x007B
        NIM_ADD, NIM_MODIFY, NIM_DELETE = 0, 1, 2
        NIF_MESSAGE, NIF_ICON, NIF_TIP, NIF_INFO = 0x1, 0x2, 0x4, 0x10
        taskbar_created = user32.RegisterWindowMessageW("TaskbarCreated")

        hinst = kernel32.GetModuleHandleW(None)

        # Icons drawn in code (see render_icon_pixels); fall back to the stock one.
        icons = {}
        fallback = user32.LoadIconW(None, 32512)  # IDI_APPLICATION
        for st in ("stopped", "running", "busy"):
            h = None
            try:
                res = icon_resource_bytes(32, render_icon_pixels(32, st))
                h = user32.CreateIconFromResourceEx(res, len(res), True, 0x00030000, 32, 32, 0)
            except Exception:
                h = None
            icons[st] = h or fallback

        def make_nid(hwnd, info=None):
            nid = NOTIFYICONDATAW()
            nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
            nid.hWnd = hwnd
            nid.uID = 1
            nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
            nid.uCallbackMessage = WM_TRAY
            nid.hIcon = icons.get(self._icon_state, icons["stopped"])
            nid.szTip = self._tooltip[:127]
            if info:
                title, text, kind = info
                nid.uFlags |= NIF_INFO
                nid.szInfoTitle = title[:63]
                nid.szInfo = text[:255]
                nid.dwInfoFlags = {"info": 0x1, "warning": 0x2, "error": 0x3}.get(kind, 0x1)
                if kind == "info":
                    nid.dwInfoFlags |= 0x10  # NIIF_NOSOUND
            return nid

        def add_icon(hwnd):
            with self._lock:
                return bool(shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(make_nid(hwnd))))

        def modify(info):
            hwnd = self._hwnd
            if not hwnd:
                return
            with self._lock:
                shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(make_nid(hwnd, info)))

        def popup_menu(hwnd):
            pt = wintypes.POINT()
            user32.GetCursorPos(ctypes.byref(pt))
            menu = user32.CreatePopupMenu()
            running = self._state != "stopped"
            MF_GRAYED, MF_SEPARATOR = 0x1, 0x800
            user32.AppendMenuW(menu, 0, 1, "Show Discord Proxy")
            user32.AppendMenuW(menu, MF_SEPARATOR, 0, None)
            user32.AppendMenuW(menu, MF_GRAYED if running else 0, 2, "Start proxy")
            user32.AppendMenuW(menu, 0 if running else MF_GRAYED, 3, "Stop proxy")
            user32.AppendMenuW(menu, MF_SEPARATOR, 0, None)
            user32.AppendMenuW(menu, 0, 4, "Exit completely")
            user32.SetForegroundWindow(hwnd)  # required so the menu closes on outside click
            # TPM_RIGHTBUTTON | TPM_NONOTIFY | TPM_RETURNCMD
            cmd = user32.TrackPopupMenu(menu, 0x0002 | 0x0080 | 0x0100, pt.x, pt.y, 0, hwnd, None)
            user32.PostMessageW(hwnd, 0, 0, 0)  # WM_NULL, per the TrackPopupMenu docs
            user32.DestroyMenu(menu)
            action = {1: "show", 2: "start", 3: "stop", 4: "exit"}.get(cmd)
            if action:
                self._cb[action]()

        def wndproc(hwnd, msg, wparam, lparam):
            try:
                if msg == WM_TRAY:
                    event = lparam & 0xFFFF
                    if event in (WM_LBUTTONUP, WM_LBUTTONDBLCLK):
                        self._cb["show"]()
                    elif event in (WM_RBUTTONUP, WM_CONTEXTMENU):
                        popup_menu(hwnd)
                    return 0
                if msg == taskbar_created:      # explorer.exe restarted
                    add_icon(hwnd)
                    return 0
                if msg == WM_CLOSE:
                    user32.DestroyWindow(hwnd)
                    return 0
                if msg == WM_DESTROY:
                    with self._lock:
                        shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(make_nid(hwnd)))
                    user32.PostQuitMessage(0)
                    return 0
            except Exception:
                pass
            return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

        wndproc_ref = WNDPROC(wndproc)  # keep a reference alive for the whole loop
        TrayIcon._counter += 1
        class_name = f"DiscordProxyTray{os.getpid()}_{TrayIcon._counter}"

        wc = WNDCLASSW()
        wc.lpfnWndProc = wndproc_ref
        wc.hInstance = hinst
        wc.lpszClassName = class_name
        if not user32.RegisterClassW(ctypes.byref(wc)):
            return
        try:
            hwnd = user32.CreateWindowExW(0, class_name, "Discord Proxy tray", 0,
                                          0, 0, 0, 0, None, None, hinst, None)
            if not hwnd or not add_icon(hwnd):
                if hwnd:
                    user32.DestroyWindow(hwnd)
                return
            self._hwnd = hwnd
            self._modify = modify
            self._ready.set()
            msg = wintypes.MSG()
            while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))
        finally:
            self._modify = None
            self._hwnd = None
            for st, h in icons.items():
                if h and h != fallback:
                    try:
                        user32.DestroyIcon(h)
                    except Exception:
                        pass
            user32.UnregisterClassW(class_name, hinst)


# ============================================================================
# Connection history (ping + drops over the last hour)
# ============================================================================

class ConnectionHistory:
    """Keeps the last HISTORY_WINDOW_S seconds of health-check results so the window can draw them.
    pings:  (wall-clock time, round trip in ms - or None for a failed probe = a "drop")
    events: (wall-clock time, kind) with kind in "reset" (voice flow reset), "failover" (link
            switched), "restart" (whole chain restarted)."""

    MAX_ITEMS = 4000

    def __init__(self):
        self.pings: collections.deque = collections.deque(maxlen=self.MAX_ITEMS)
        self.events: collections.deque = collections.deque(maxlen=self.MAX_ITEMS)

    def add_ping(self, ms) -> None:
        self.pings.append((time.time(), None if ms is None or ms < 0 else int(ms)))

    def add_event(self, kind: str) -> None:
        self.events.append((time.time(), kind))

    def _prune(self, now: float) -> None:
        cutoff = now - HISTORY_WINDOW_S
        while self.pings and self.pings[0][0] < cutoff:
            self.pings.popleft()
        while self.events and self.events[0][0] < cutoff:
            self.events.popleft()

    def snapshot(self, now: float | None = None):
        now = now or time.time()
        self._prune(now)
        return list(self.pings), list(self.events)

    def stats(self, now: float | None = None):
        """(average ms, max ms, drops, total samples) over the window; averages are None without data."""
        pings, _ev = self.snapshot(now)
        ok = [ms for _t, ms in pings if ms is not None]
        drops = sum(1 for _t, ms in pings if ms is None)
        return (sum(ok) / len(ok) if ok else None), (max(ok) if ok else None), drops, len(pings)


# ============================================================================
# Voice quality probe: ping / packet loss / jitter through the SAME proxy
#
# sing-box's local API only exposes byte counters per flow - no packet counts, no timing - so the
# real loss/jitter of Discord's own RTP packets cannot be read from it. What CAN be measured
# honestly is the quality of the UDP path through the proxy that carries the call: while a voice
# call is active, a tiny DNS query (~35 bytes, 4 per second) is sent through a loopback "direct"
# inbound of the generated config, which routes it through the same outbound as Discord's voice
# flow. Unanswered queries = loss, the answer times = ping, their variation = jitter.
# ============================================================================

def _free_udp_port() -> int:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _dns_probe_packet(txid: int) -> bytes:
    name = b"".join(bytes([len(p)]) + p.encode("ascii") for p in "cp.cloudflare.com".split(".")) + b"\x00"
    return struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0) + name + struct.pack(">HH", 1, 1)


class VoiceQualityProbe:
    INTERVAL_S = 0.25
    TIMEOUT_S = 0.9
    WINDOW = 80            # probes in the rolling window (about 20 s)
    MIN_SAMPLES = 12
    REPORT_S = 2.0

    def __init__(self, probe_port: int, status: "VoiceStatus", on_update):
        self.probe_port, self.status, self.on_update = probe_port, status, on_update
        self._win: collections.deque = collections.deque(maxlen=self.WINDOW)   # rtt in ms, None = lost
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()

    @staticmethod
    def summarize(window) -> dict:
        """ping (median ms), loss (%), jitter (mean |difference| of consecutive answers, ms)."""
        import statistics
        n = len(window)
        rtts = [x for x in window if x is not None]
        out = {"samples": n, "ping": None, "loss": None, "jitter": None, "dead": False}
        if not n:
            return out
        out["loss"] = (n - len(rtts)) * 100.0 / n
        if rtts:
            out["ping"] = statistics.median(rtts)
            if len(rtts) > 1:
                out["jitter"] = sum(abs(a - b) for a, b in zip(rtts, rtts[1:])) / (len(rtts) - 1)
            else:
                out["jitter"] = 0.0
        out["dead"] = n >= VoiceQualityProbe.MIN_SAMPLES and not rtts
        return out

    def _report(self):
        try:
            self.on_update(self.summarize(self._win))
        except Exception:
            pass

    def _run(self):
        import socket
        sock = None
        last_report = 0.0
        idle_reported = True
        try:
            while not self._stop.is_set():
                if not self.status.in_call():
                    if not idle_reported:
                        self._win.clear()
                        idle_reported = True
                        self._report()
                    if sock is not None:
                        sock.close()
                        sock = None
                    self._stop.wait(1.0)
                    continue
                idle_reported = False
                if sock is None:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.connect(("127.0.0.1", self.probe_port))
                    sock.settimeout(self.TIMEOUT_S)
                t0 = time.perf_counter()
                txid = secrets.randbits(16)
                rtt = None
                try:
                    sock.send(_dns_probe_packet(txid))
                    deadline = t0 + self.TIMEOUT_S
                    while True:
                        left = deadline - time.perf_counter()
                        if left <= 0:
                            break
                        sock.settimeout(left)
                        data = sock.recv(512)
                        if len(data) >= 2 and struct.unpack(">H", data[:2])[0] == txid:
                            rtt = (time.perf_counter() - t0) * 1000.0
                            break          # a late answer to an OLDER probe is ignored (already counted lost)
                except (socket.timeout, OSError):
                    pass
                self._win.append(rtt)
                now = time.monotonic()
                if now - last_report >= self.REPORT_S:
                    last_report = now
                    self._report()
                self._stop.wait(max(0.0, self.INTERVAL_S - (time.perf_counter() - t0)))
        finally:
            if sock is not None:
                sock.close()


def quality_grade(ping, loss, jitter) -> str:
    """'good' | 'fair' | 'bad' for the voice quality line."""
    ping = ping if ping is not None else 0
    loss = loss if loss is not None else 0
    jitter = jitter if jitter is not None else 0
    if loss >= 5 or jitter >= 40 or ping >= 300:
        return "bad"
    if loss >= 1 or jitter >= 20 or ping >= 150:
        return "fair"
    return "good"


# ============================================================================
# Saved links (several proxy links, failover order, "test all" latency ranking)
# ============================================================================

MAX_SAVED_LINKS = 50
_SUPPORTED_SCHEMES = ("vless", "vmess", "trojan", "ss", "hysteria2", "hy2", "tuic", "wireguard", "wg")


def default_link_name(text: str) -> str:
    """A readable label for a saved link: the #name in the link, vmess "ps", else scheme://host:port."""
    text = (text or "").strip()
    try:
        if text.lower().startswith("vmess://"):
            data = json.loads(_b64decode_flexible(text[8:]).decode("utf-8", "replace"))
            if isinstance(data, dict) and data.get("ps"):
                return str(data["ps"])[:48]
        sp = urlsplit(text)
        if sp.fragment:
            return unquote(sp.fragment)[:48]
        if sp.hostname:
            return f"{sp.scheme}://{sp.hostname}" + (f":{sp.port}" if sp.port else "")
    except Exception:
        pass
    return (text[:24] + "...") if len(text) > 24 else (text or "link")


def extract_links(text: str) -> list:
    """Every supported proxy link found in a blob of text (one per line, or run together)."""
    seen, out = set(), []
    for m in re.finditer(r"\b(?:%s)://\S+" % "|".join(_SUPPORTED_SCHEMES), text or "", re.I):
        link = m.group(0).strip().rstrip(",;")
        if link not in seen:
            seen.add(link)
            out.append(link)
    return out


def sanitize_links(value) -> list:
    out, seen = [], set()
    if not isinstance(value, list):
        return out
    for item in value:
        if not isinstance(item, dict):
            continue
        link = item.get("link")
        if not isinstance(link, str) or not link.strip() or link.strip() in seen:
            continue
        seen.add(link.strip())
        name = item.get("name") if isinstance(item.get("name"), str) and item.get("name").strip() \
            else default_link_name(link)
        out.append({"name": name.strip()[:60], "link": link.strip()})
        if len(out) >= MAX_SAVED_LINKS:
            break
    return out


_TEST_MGRS: list = []     # throw-away sing-box / xray instances of "Test all" (killed on exit)
_TEST_MGRS_LOCK = threading.Lock()


def kill_test_processes() -> None:
    with _TEST_MGRS_LOCK:
        mgrs = list(_TEST_MGRS)
        _TEST_MGRS.clear()
    for m in mgrs:
        try:
            m.stop()
        except Exception:
            pass


def measure_link_latency(text: str, core: str, bypass_tun: bool, cancel: threading.Event | None = None):
    """Starts a throw-away sing-box (+ xray when the link needs it) for ONE saved link, with no TUN and
    no admin, and times a few HTTPS requests to Discord's gateway through it.
    Returns (ok, median_ms_or_None, short_note). Never raises."""
    import urllib.request
    import urllib.error
    outbound, err = parse_proxy_link(text)
    if err or outbound is None:
        return False, None, "invalid link"
    if not os.path.isfile(singbox_exe_path()):
        return False, None, "sing-box.exe missing"
    cfg_path, xcfg_path = testall_config_path(), xray_testall_config_path()
    mgr = xmgr = None
    try:
        try:
            outbound, xmgr = start_xray_chain_if_needed(outbound, lambda _m: None, core, loglevel="warning",
                                                        config_path=xcfg_path)
        except Exception as ex:
            return False, None, (str(ex).strip().splitlines() or ["error"])[0][:70]
        if xmgr:
            with _TEST_MGRS_LOCK:
                _TEST_MGRS.append(xmgr)
        port = _free_local_port()
        os.makedirs(config_dir(), exist_ok=True)
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(build_test_config(outbound, port, bypass_tun), f, indent=2)
        mgr = SingBoxManager(on_log=lambda _l: None, on_exit=lambda _c: None, cleanup_adapter=False)
        with _TEST_MGRS_LOCK:
            _TEST_MGRS.append(mgr)
        mgr.start(cfg_path)
        for _ in range(8):                       # up to ~2 s for the local listener
            if (cancel and cancel.is_set()) or not mgr.is_running:
                break
            time.sleep(0.25)
        if not mgr.is_running:
            return False, None, "sing-box did not start"
        proxy = f"http://127.0.0.1:{port}"
        ctx, _verified = make_ssl_context()      # only proves the tunnel carries traffic, like Test Proxy
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy}),
            urllib.request.HTTPSHandler(context=ctx))
        req_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                                     "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"}
        times, last_err = [], ""
        for i in range(4):                       # first request also warms the connection up
            if cancel and cancel.is_set():
                return False, None, "cancelled"
            t0 = time.perf_counter()
            try:
                try:
                    with opener.open(urllib.request.Request(HealthMonitor.GATEWAY_URL, headers=req_headers),
                                     timeout=8):
                        pass
                except urllib.error.HTTPError:
                    pass                          # any HTTP answer from discord.com proves the tunnel works
                times.append((time.perf_counter() - t0) * 1000.0)
            except Exception as ex:
                reason = getattr(ex, "reason", ex)
                last_err = ("timed out" if "timed out" in str(reason).lower() else type(reason).__name__)
        if not times:
            return False, None, last_err or "no answer"
        use = times[1:] if len(times) >= 3 else times
        use = sorted(use)
        return True, int(use[len(use) // 2]), (f"{4 - len(times)} of 4 failed" if len(times) < 4 else "")
    except Exception as ex:
        return False, None, mask_secrets(str(ex))[:70]
    finally:
        for m in (mgr, xmgr):
            if m is not None:
                try:
                    m.stop()
                except Exception:
                    pass
                with _TEST_MGRS_LOCK:
                    if m in _TEST_MGRS:
                        _TEST_MGRS.remove(m)
        for path in (cfg_path, xcfg_path):
            try:
                if os.path.exists(path):
                    os.remove(path)
            except OSError:
                pass


# ============================================================================
# Release lookups (update checker) and component downloads
#
# Everything here talks only to the official sources, over HTTPS, and only when the person
# asked for it (the update check can be switched off; downloads need a confirmation):
#   sing-box  github.com/SagerNet/sing-box     Xray-core  github.com/XTLS/Xray-core
#   wintun    www.wintun.net
# The latest tag is read from github.com's own "releases/latest" redirect, so no API quota applies.
# ============================================================================

SINGBOX_REPO = "SagerNet/sing-box"
XRAY_REPO = "XTLS/Xray-core"
WINTUN_FALLBACK_VERSION = "0.14.1"
_HTTP_UA = {"User-Agent": "DiscordProxy/1.0 (official-release-check)"}

COMPONENTS = {
    "sing-box": {"file": "sing-box.exe", "required": True,
                 "source": "github.com/SagerNet/sing-box - official release"},
    "wintun": {"file": "wintun.dll", "required": True,
               "source": "www.wintun.net - official site"},
    "xray": {"file": "xray.exe", "required": False,
             "source": "github.com/XTLS/Xray-core - official release (only needed for XHTTP / mKCP links)"},
}
_ARCH_LABEL = {"amd64": "64-bit (x64)", "arm64": "ARM64", "386": "32-bit (x86)"}


class DownloadError(Exception):
    pass


def native_arch() -> str:
    """'amd64' | 'arm64' | '386' - the PC's real architecture (also when this Python is an emulated
    x64 build on ARM64 Windows), because sing-box.exe, xray.exe and wintun.dll must all match it."""
    if os.name == "nt":
        try:
            k32 = ctypes.windll.kernel32
            k32.GetCurrentProcess.restype = ctypes.c_void_p
            k32.IsWow64Process2.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ushort),
                                            ctypes.POINTER(ctypes.c_ushort)]
            proc, native = ctypes.c_ushort(), ctypes.c_ushort()
            if k32.IsWow64Process2(k32.GetCurrentProcess(), ctypes.byref(proc), ctypes.byref(native)):
                got = {0x8664: "amd64", 0xAA64: "arm64", 0x014C: "386"}.get(native.value)
                if got:
                    return got
        except Exception:
            pass
    raw = (os.environ.get("PROCESSOR_ARCHITEW6432") or os.environ.get("PROCESSOR_ARCHITECTURE")
           or platform.machine() or "").lower()
    if "arm64" in raw or "aarch64" in raw:
        return "arm64"
    if raw in ("x86", "i386", "i686"):
        return "386"
    return "amd64"


def _tls_context_or_raise():
    ctx, verified = make_ssl_context()
    if not verified:
        raise DownloadError("no usable certificate store was found on this PC, so the HTTPS connection "
                            "cannot be verified - not downloading programs without verification")
    return ctx


def _open_https(url: str, ctx, timeout: float = 30.0):
    class _HttpsOnly(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            if not newurl.lower().startswith("https://"):
                raise DownloadError("refused a redirect to a non-HTTPS address")
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), _HttpsOnly())
    return opener.open(urllib.request.Request(url, headers=_HTTP_UA), timeout=timeout)


def _fetch_text(url: str, ctx, limit: int = 3_000_000) -> str:
    with _open_https(url, ctx) as r:
        return r.read(limit).decode("utf-8", "replace")


def latest_release_tag(repo: str, ctx=None) -> str:
    """Tag of the newest stable release, e.g. 'v1.14.3'."""
    ctx = ctx or make_ssl_context()[0]

    class _NoFollow(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None

    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), _NoFollow())
    req = urllib.request.Request(f"https://github.com/{repo}/releases/latest", method="HEAD", headers=_HTTP_UA)
    try:
        opener.open(req, timeout=15)
    except urllib.error.HTTPError as ex:
        m = re.search(r"/releases/tag/([^/?#]+)", ex.headers.get("Location") or "")
        if ex.code in (301, 302, 303, 307, 308) and m:
            return unquote(m.group(1))
        raise DownloadError(f"unexpected answer from github.com (HTTP {ex.code})")
    raise DownloadError("github.com did not name a latest release")


def _tag_version(tag: str):
    m = _VERSION_RE.search((tag or "").lstrip("vV"))     # \b would not match between "v" and the digits
    return tuple(int(x) for x in m.groups()) if m else None


def release_asset_sha256(repo: str, tag: str, filename: str, ctx) -> str | None:
    """The SHA-256 GitHub publishes for a release asset (None when the page does not show one)."""
    try:
        html = _fetch_text(f"https://github.com/{repo}/releases/expanded_assets/{tag}", ctx)
    except Exception:
        return None
    needle = f"/download/{tag}/{filename}\""
    for block in re.split(r"<li\b", html):
        if needle in block:
            m = re.search(r"sha256:([0-9a-fA-F]{64})", block)
            if m:
                return m.group(1).lower()
    return None


def check_core_updates(ctx=None) -> list:
    """For each core present next to the script: installed vs. latest official release.
    [{name, installed, latest, outdated, url, error}] - never raises."""
    out = []
    for name, repo, exe, args in (
            ("sing-box", SINGBOX_REPO, singbox_exe_path(), (["version"],)),
            ("xray-core", XRAY_REPO, xray_exe_path(), (["version"], ["-version"]))):
        if not os.path.isfile(exe):
            continue
        item = {"name": name, "installed": None, "latest": None, "outdated": False,
                "url": f"https://github.com/{repo}/releases/latest", "error": ""}
        try:
            item["installed"] = core_version(exe, args)
            tag = latest_release_tag(repo, ctx)
            item["latest"] = _tag_version(tag)
            item["url"] = f"https://github.com/{repo}/releases/tag/{tag}"
            item["outdated"] = bool(item["installed"] and item["latest"] and item["latest"] > item["installed"])
        except Exception as ex:
            item["error"] = str(ex)[:100]
        out.append(item)
    return out


def _wintun_versions(ctx) -> list:
    """Versions to try, newest first: whatever www.wintun.net links to, then the known-good fallback."""
    found = []
    try:
        html = _fetch_text("https://www.wintun.net/", ctx)
        found = sorted(set(re.findall(r"builds/wintun-(\d+(?:\.\d+)+)\.zip", html)),
                       key=lambda v: tuple(int(x) for x in v.split(".")), reverse=True)
    except Exception:
        pass
    if WINTUN_FALLBACK_VERSION not in found:
        found.append(WINTUN_FALLBACK_VERSION)
    return found[:3]


def _verify_authenticode(path: str):
    """True / False from Windows' own signature check, None when it could not be run."""
    p = path.replace("'", "''")
    cmd = ("$s = Get-AuthenticodeSignature -LiteralPath '%s'; "
           "$s.Status.ToString() + '|' + [string]$s.SignerCertificate.Subject" % p)
    code, out = _run_tool(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                           "-Command", cmd], 40)
    if code is None:
        return None
    lines = (out or "").strip().splitlines()
    if not lines:
        return False
    status, _sep, subject = lines[-1].partition("|")
    return status.strip() == "Valid" and "wireguard" in subject.lower()


def _extract_member(zip_path: str, pick, dest: str, max_bytes: int) -> None:
    """Copies ONE member of the zip (chosen by pick(name) -> bool) to `dest`. Never uses extractall,
    never trusts a path inside the archive."""
    with zipfile.ZipFile(zip_path) as zf:
        matches = [i for i in zf.infolist() if not i.is_dir() and pick(i.filename.replace("\\", "/"))]
        if not matches:
            raise DownloadError("the downloaded archive does not contain the expected file")
        info = matches[0]
        if info.file_size > max_bytes:
            raise DownloadError("the file inside the archive is unexpectedly large")
        with zf.open(info) as src, open(dest, "wb") as out:
            shutil.copyfileobj(src, out, 1024 * 256)


def _download_to(url: str, ctx, dest: str, cancel, progress, label: str, max_bytes: int) -> str:
    h = hashlib.sha256()
    got = 0
    with _open_https(url, ctx, timeout=30) as r, open(dest, "wb") as f:
        total = int(r.headers.get("Content-Length") or 0)
        while True:
            if cancel.is_set():
                raise DownloadError("cancelled")
            chunk = r.read(64 * 1024)
            if not chunk:
                break
            got += len(chunk)
            if got > max_bytes:
                raise DownloadError("the download is larger than expected - stopped")
            h.update(chunk)
            f.write(chunk)
            progress(label, (got / total) if total else None)
    return h.hexdigest()


def _install_component(comp: str, arch: str, ctx, cancel, progress) -> str:
    """Downloads, verifies and installs one component next to the script. Returns a one-line summary."""
    os.makedirs(downloads_dir(), exist_ok=True)
    info = COMPONENTS[comp]
    target = os.path.join(base_dir(), info["file"])
    label = info["file"]
    expected = None
    if comp in ("sing-box", "xray"):
        repo = SINGBOX_REPO if comp == "sing-box" else XRAY_REPO
        progress(f"{label}: looking up the latest release...", None)
        tag = latest_release_tag(repo, ctx)
        if comp == "sing-box":
            asset = f"sing-box-{tag.lstrip('v')}-windows-{arch}.zip"
            pick = lambda n: n.lower().rsplit("/", 1)[-1] == "sing-box.exe"
        else:
            asset = {"amd64": "Xray-windows-64.zip", "arm64": "Xray-windows-arm64-v8a.zip",
                     "386": "Xray-windows-32.zip"}[arch]
            pick = lambda n: n.lower().rsplit("/", 1)[-1] == "xray.exe"
        candidates = [f"https://github.com/{repo}/releases/download/{tag}/{asset}"]
        expected = release_asset_sha256(repo, tag, asset, ctx)
        version_text = tag
        max_zip, max_file = 120_000_000, 150_000_000
    else:  # wintun
        wdir = {"amd64": "amd64", "arm64": "arm64", "386": "x86"}[arch]
        versions = _wintun_versions(ctx)
        candidates = [f"https://www.wintun.net/builds/wintun-{v}.zip" for v in versions]
        pick = lambda n, d=wdir: n.lower().endswith(f"/bin/{d}/wintun.dll")
        version_text = "wintun " + versions[0]
        asset = "wintun.zip"
        max_zip, max_file = 10_000_000, 5_000_000

    zip_path = os.path.join(downloads_dir(), asset)
    last_error = ""
    digest = None
    for url in candidates:
        try:
            digest = _download_to(url, ctx, zip_path, cancel, progress, f"{label}: downloading...", max_zip)
            if comp == "wintun":
                version_text = "wintun " + url.rsplit("wintun-", 1)[-1][:-4]
            break
        except DownloadError:
            raise
        except urllib.error.HTTPError as ex:
            last_error = f"HTTP {ex.code} from {urlsplit(url).netloc}"
        except Exception as ex:
            last_error = str(getattr(ex, "reason", ex))
    if digest is None:
        raise DownloadError(f"could not download {label}: {last_error or 'no answer'}")
    try:
        verified = ""
        if expected:
            if digest != expected:
                raise DownloadError(f"{label}: the SHA-256 of the download does not match the one published "
                                    "on the official release page - refusing to install it")
            verified = "SHA-256 verified"
        progress(f"{label}: unpacking...", None)
        tmp = target + ".new"
        _extract_member(zip_path, pick, tmp, max_file)
        try:
            if comp == "wintun":
                progress(f"{label}: checking the digital signature...", None)
                sig = _verify_authenticode(tmp)
                if sig is False:
                    raise DownloadError("wintun.dll does not carry a valid WireGuard digital signature - "
                                        "refusing to install it")
                verified = "WireGuard signature verified" if sig else "signature could not be checked"
            elif not expected:
                verified = "no published checksum to compare"
            os.replace(tmp, target)
        finally:
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except OSError:
                pass
    finally:
        try:
            os.remove(zip_path)
        except OSError:
            pass
    return f"{info['file']} installed ({version_text}, {_ARCH_LABEL.get(arch, arch)}; {verified})"


def install_components(comps: list, arch: str, progress, cancel) -> list:
    """Returns [(component, ok, message)]. Runs in a worker thread."""
    results = []
    try:
        ctx = _tls_context_or_raise()
    except DownloadError as ex:
        return [(c, False, str(ex)) for c in comps]
    for i, comp in enumerate(comps):
        if cancel.is_set():
            results.append((comp, False, "cancelled"))
            continue
        base = i / max(1, len(comps))
        span = 1.0 / max(1, len(comps))

        def prog(text, frac, base=base, span=span):
            progress(text, base + span * frac if frac is not None else base)

        try:
            results.append((comp, True, _install_component(comp, arch, ctx, cancel, prog)))
        except DownloadError as ex:
            results.append((comp, False, str(ex)))
        except PermissionError:
            results.append((comp, False, f"{COMPONENTS[comp]['file']} is in use or the folder is read-only - "
                                         "close the program that uses it and try again"))
        except Exception as ex:
            results.append((comp, False, f"{type(ex).__name__}: {ex}"))
    return results


# ============================================================================
# Start with Windows (Task Scheduler: runs elevated at sign-in with no UAC prompt)
# ============================================================================

def autostart_command():
    """(program, arguments) the sign-in task runs: this script, started in the tray."""
    if getattr(sys, "frozen", False):
        return sys.executable, "--tray"
    exe = sys.executable
    pyw = os.path.join(os.path.dirname(exe), "pythonw.exe")      # no console window
    if os.path.basename(exe).lower() == "python.exe" and os.path.isfile(pyw):
        exe = pyw
    return exe, f'"{_SCRIPT_PATH}" --tray'


def build_task_xml(delay_s: int) -> str:
    user = (os.environ.get("USERDOMAIN", "") + "\\" + os.environ.get("USERNAME", "")).strip("\\")
    exe, args = autostart_command()
    delay = f"<Delay>PT{int(delay_s)}S</Delay>" if delay_s else ""
    return (
        '<?xml version="1.0" encoding="UTF-16"?>\n'
        '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\n'
        "  <RegistrationInfo><Description>Starts Discord Proxy in the system tray when you sign in."
        "</Description></RegistrationInfo>\n"
        f"  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{xml_escape(user)}</UserId>{delay}"
        "</LogonTrigger></Triggers>\n"
        f'  <Principals><Principal id="Author"><UserId>{xml_escape(user)}</UserId>'
        "<LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>\n"
        "  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"
        "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"
        "<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate>"
        "<StartWhenAvailable>false</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>"
        "<AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden>"
        "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>7</Priority></Settings>\n"
        '  <Actions Context="Author"><Exec>'
        f"<Command>{xml_escape(exe)}</Command><Arguments>{xml_escape(args)}</Arguments>"
        f"<WorkingDirectory>{xml_escape(base_dir())}</WorkingDirectory></Exec></Actions>\n"
        "</Task>\n"
    )


def autostart_exists() -> bool:
    if os.name != "nt":
        return False
    code, _out = _run_tool(["schtasks", "/Query", "/TN", AUTOSTART_TASK], 15)
    return code == 0


def autostart_enable(delay_s: int):
    """(ok, message). Needs Administrator (the task runs with highest privileges)."""
    if os.name != "nt":
        return False, "Windows only"
    if not is_admin():
        return False, "Administrator rights are needed to create the sign-in task."
    os.makedirs(config_dir(), exist_ok=True)
    xml_path = os.path.join(config_dir(), "autostart_task.xml")
    try:
        with open(xml_path, "w", encoding="utf-16") as f:
            f.write(build_task_xml(delay_s))
        code, out = _run_tool(["schtasks", "/Create", "/TN", AUTOSTART_TASK, "/XML", xml_path, "/F"], 30)
    finally:
        try:
            os.remove(xml_path)
        except OSError:
            pass
    if code == 0:
        return True, "ok"
    return False, (out or "schtasks failed")[:300]


def autostart_disable():
    if os.name != "nt":
        return False, "Windows only"
    if not autostart_exists():
        return True, "ok"
    code, out = _run_tool(["schtasks", "/Delete", "/TN", AUTOSTART_TASK, "/F"], 20)
    if code == 0:
        return True, "ok"
    return False, ((out or "schtasks failed")[:300] if is_admin()
                   else "Administrator rights are needed to remove the sign-in task.")


# ============================================================================
# Live log filters
# ============================================================================

_LOG_ERR_RE = re.compile(r"\b(error|fatal|panic|failed|failure|exception|refused|rejected|denied|timed out|"
                         r"timeout|unreachable|could not|gave up|not answering|no answer|stopped unexpectedly)\b",
                         re.I)
_LOG_DISCORD_RE = re.compile("|".join(re.escape(s) for s in DISCORD_DOMAIN_SUFFIXES) + r"|discord|voice", re.I)


PLACEHOLDER = "Paste a proxy link (vless://, vmess://, trojan://, ss://...) or outbound JSON."


class DiscordProxyApp(tk.Tk):
    def __init__(self, single=None, start_hidden: bool = False):
        super().__init__()
        self._start_hidden = start_hidden
        if start_hidden:
            self.withdraw()          # sign-in launch: no window flash, tray icon only
        self.title("Discord Proxy")
        self.resizable(False, False)          # fixed size - see _fit_window()

        self._single = single
        self._default_bg = self.cget("bg")
        self._pal = dict(LIGHT_PALETTE, bg=self._default_bg)
        self._is_dark = False
        self._default_ttk_theme = ""
        self._themed_menus: list = []
        self._muted_labels: list = []
        self._settings_win = None
        self._theme_ready = False
        self._manager = SingBoxManager(on_log=self._on_log_bg, on_exit=self._on_exit_bg)
        self._xray: XrayManager | None = None  # only created when Xray-core carries the connection
        self._monitor: TrafficMonitor | None = None
        self._event_queue: "queue.Queue[tuple]" = queue.Queue()
        self._log_lines = collections.deque(maxlen=50000)
        self._settings = load_settings()
        self._restore_geometry()
        self._active_core = ""
        self._tray: TrayIcon | None = None
        self._exiting = False
        self._api: dict | None = None      # stats-API port/secret of the current run
        self._launch_token = 0             # bumped by Stop/Start so stale launches are ignored
        self._proc_token = 0               # token of the sing-box process currently running
        self._retry = 0                    # automatic TUN-adapter retries used so far
        self._launch_time = 0.0
        self._log_total = 0                # lines ever logged (the deque is capped)
        self._log_start = 0                # value of _log_total when this launch began
        self._state = "stopped"            # stopped | starting | running | retrying
        self._want_running = False         # True between a Start and the next Stop / failure
        self._recovering = False           # a restart of the whole chain is in progress
        self._recover_times: list = []
        self._last_text = ""
        self._health: HealthMonitor | None = None
        self._voice_wd: VoiceStallWatchdog | None = None
        self._voice_status = VoiceStatus()
        self._voice_last = ("idle", 0.0, 0.0, 0)   # what the Voice line shows
        self._ping_ms: int | None = None           # median proxy round trip; -1 = proxy not answering
        self._guard_notified = False               # mid-call guard notice already shown for this outage
        self._last_health_note = ""
        self._xray_port: int | None = None
        self._xray_swapping = False        # xray alone is being restarted (sing-box/TUN stay up)
        self._health_fail = 0
        self._health_lost = False
        self._health_restarted = False
        self._announce_restored = False
        self._auto_started = False         # the running proxy was started by auto mode
        self._auto_suppressed = False      # auto mode paused until Discord closes
        self._discord_gone_since: float | None = None
        self._cleanup_pending = False
        self._hint_shown = False
        self._learned: set = set(read_ranges_file(learned_ranges_path())[0])
        self._learning_note_shown = False
        self._capture_active = "all"       # capture mode the current run really uses
        self._force_all = False            # voice fallback: capture everything for this run
        self._learning_run = False         # this run is a range-learning / capture-everything fallback pass
        self._ks_engaged = False           # kill switch: Discord is currently firewalled off
        self._ks_gen = 0
        self._voice_deadline: float | None = None
        self._voice_return_gen = 0         # cancels stale 'return to Discord-only' timers
        self._early_return_pending = False  # a quick 'back to Discord-only' is scheduled
        self._early_returned: set = set()   # ranges we already returned early for (no loops)
        self._voice_return_state: dict = {}
        self._geo_job = None
        self._discord_closing = False      # a "Close Discord" run is in progress
        self._history = ConnectionHistory()
        self._voice_probe: VoiceQualityProbe | None = None
        self._voiceq: dict | None = None
        self._link_results: dict = {}      # link text -> "testing" | {ok, ms, note}
        self._link_failed_at: dict = {}    # link text -> monotonic time it last failed (failover skips it)
        self._links_win = None
        self._links_tree = None
        self._link_meta_cache: dict = {}
        self._testall_running = False
        self._testall_cancel = threading.Event()
        self._update_results: list = []
        self._update_logged: dict = {}
        self._dl_win = None
        self._dl_then = None
        self._dl_cancel = threading.Event()
        self._dl_prompted = False
        self._log_shown = 0
        self._log_clear_at = 0
        self._log_refilter_job = None

        self._build_ui()
        self._fit_window()
        self.input_box.bind("<FocusOut>", self._remember_link, add="+")
        self.bind("<Configure>", self._on_configure)
        self._collect_muted(self)
        self._apply_theme()
        self._theme_ready = True
        self._apply_window_icon("stopped")
        saved_link = (self._settings.get("link") or "").strip()
        if saved_link:
            self.input_box.delete("1.0", "end")
            self.input_box.insert("1.0", saved_link)
        self._tray = TrayIcon(
            on_show=lambda: self._event_queue.put(("tray", "show")),
            on_exit=lambda: self._event_queue.put(("tray", "exit")),
            on_start=lambda: self._event_queue.put(("tray", "start")),
            on_stop=lambda: self._event_queue.put(("tray", "stop")),
        )
        self.after(200, self._start_tray)
        self._apply_log_panel_visibility()
        self._links_refresh_tree()
        self._links_status_refresh()
        self._redraw_history()
        self._refresh_voiceq()
        self.after(60000, self._history_tick)
        self.after(1500, self._startup_download_prompt)
        self.after(2500, self._autostart_refresh)
        self.after(1200, self._ks_startup_check)
        self.after(8000, self._update_tick)
        if start_hidden:
            self._hint_shown = True
            self.after(1200, self._startup_hide)
        self._begin_startup_cleanup()
        if self._single:
            self._single.listen(lambda: self._event_queue.put(("tray", "show")))
        self.after(100, self._drain_event_queue)
        self.after(300, self.refresh_all_status)
        self.after(3000, self._status_tick)

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---------------------------------------------------------------- UI

    def _build_ui(self):
        body = ttk.Frame(self)
        body.pack(fill="both", expand=True)
        body.grid_columnconfigure(0, minsize=WIN_WIDTH)
        body.grid_columnconfigure(1, weight=1, minsize=SIDE_WIDTH)
        body.grid_rowconfigure(0, weight=1)
        root = ttk.Frame(body, padding=16)
        root.grid(row=0, column=0, sticky="nsw")
        wrap = WIN_WIDTH - 40

        header = ttk.Frame(root)
        header.pack(fill="x", pady=(0, 10))
        ttk.Label(header, text="Discord Proxy", font=("Segoe UI", 18, "bold")).pack(side="left")
        ttk.Button(header, text="Settings", command=self._open_settings).pack(side="right")

        # --- status panel ---
        status_box = ttk.LabelFrame(root, text="Status", padding=10)
        status_box.pack(fill="x", pady=(0, 10))
        grid = ttk.Frame(status_box)
        grid.pack(fill="x")
        grid.columnconfigure(0, weight=1)
        grid.columnconfigure(1, weight=1)

        self.lbl_singbox = ttk.Label(grid, text="● sing-box.exe: checking...")
        self.lbl_singbox.grid(row=0, column=0, sticky="w")
        self.lbl_wintun = ttk.Label(grid, text="● wintun.dll: checking...")
        self.lbl_wintun.grid(row=1, column=0, sticky="w", pady=(4, 0))
        self.lbl_admin = ttk.Label(grid, text="● Administrator: checking...")
        self.lbl_admin.grid(row=0, column=1, sticky="w")
        self.lbl_discord = ttk.Label(grid, text="● Discord: checking...")
        self.lbl_discord.grid(row=1, column=1, sticky="w", pady=(4, 0))
        self.lbl_xray = ttk.Label(grid, text="● xray-core: checking...")
        self.lbl_xray.grid(row=2, column=0, columnspan=2, sticky="w", pady=(4, 0))

        btn_row = ttk.Frame(status_box)
        btn_row.pack(fill="x", pady=(8, 0))
        ttk.Button(btn_row, text="Re-check", command=self.refresh_all_status).pack(side="left")
        self.btn_elevate = ttk.Button(btn_row, text="Restart as Administrator", command=self._restart_elevated)
        self.btn_elevate.pack(side="left", padx=(8, 0))
        if is_admin():
            self.btn_elevate.state(["disabled"])
        self.btn_update = ttk.Button(btn_row, text="Update", command=self._update_components)
        self.btn_getfiles = ttk.Button(btn_row, text="Get missing files...", command=lambda: self._offer_download())
        self.update_box = ttk.Frame(status_box)     # "update available" lines (clickable)
        self.update_box.pack(fill="x")

        # --- the active link lives in this hidden box; it is chosen in the server list on the right ---
        self.input_box = tk.Text(root, height=1, width=10, wrap="word", font=("Consolas", 10))
        self.input_box.insert("1.0", PLACEHOLDER)
        self.input_box.bind("<FocusIn>", self._clear_placeholder)
        self.input_box.bind("<FocusOut>", self._restore_placeholder)
        self._attach_context_menu(self.input_box)

        # --- proxy core selector ---
        core_row = ttk.Frame(root)
        core_row.pack(fill="x", pady=(0, 10))
        ttk.Label(core_row, text="Proxy core:", font=("Segoe UI", 10, "bold")).pack(side="left")
        saved = self._settings.get("core", "auto")
        label_for = {v: k for k, v in CORE_CHOICES.items()}
        self.core_var = tk.StringVar(value=label_for.get(saved, "Auto (recommended)"))
        self.core_combo = ttk.Combobox(core_row, textvariable=self.core_var, state="readonly",
                                       values=list(CORE_CHOICES.keys()), width=22)
        self.core_combo.pack(side="left", padx=(8, 0))
        self.core_combo.bind("<<ComboboxSelected>>", self._on_core_changed)

        # --- buttons (two rows so they fit the narrow window) ---
        btns = ttk.Frame(root)
        btns.pack(fill="x", pady=(0, 4))
        self.btn_start = ttk.Button(btns, text="Start Discord Proxy", command=self.start_proxy)
        self.btn_start.pack(side="left")
        self.btn_stop = ttk.Button(btns, text="Stop", command=self.stop_proxy, state="disabled")
        self.btn_stop.pack(side="left", padx=(8, 0))
        self.btn_test = ttk.Button(btns, text="Test Proxy", command=self.test_proxy)
        self.btn_test.pack(side="left", padx=(8, 0))
        self.btn_retry = ttk.Button(btns, text="Retry", command=self.retry_connection)
        self.btn_retry.pack(side="left", padx=(8, 0))
        btns2 = ttk.Frame(root)
        btns2.pack(fill="x", pady=(0, 4))
        ttk.Button(btns2, text="Open Config Folder", command=self.open_config_folder).pack(side="left")
        ttk.Button(btns2, text="Export Log (.txt)", command=self.export_log).pack(side="left", padx=(8, 0))
        btns3 = ttk.Frame(root)
        btns3.pack(fill="x", pady=(0, 10))
        ttk.Button(btns3, text="Open Discord", command=self.open_discord).pack(side="left")
        self.btn_close_discord = ttk.Button(btns3, text="Close Discord", command=self.close_discord)
        self.btn_close_discord.pack(side="left", padx=(8, 0))

        # --- traffic / voice (the live log is intentionally hidden - use "Export Log (.txt)") ---
        ttk.Label(root, text="Traffic", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.lbl_traffic = ttk.Label(root, text=self._traffic_text(0, 0), font=("Consolas", 9))
        self.lbl_traffic.pack(anchor="w", pady=(0, 8))

        ttk.Label(root, text="Voice", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.lbl_voice = ttk.Label(root, text=self._voice_text(*self._voice_last), font=("Consolas", 9))
        self.lbl_voice.pack(anchor="w", pady=(0, 2))
        self.lbl_voiceq = ttk.Label(root, text="quality: not running\n ", font=("Consolas", 9), justify="left")
        self.lbl_voiceq.pack(anchor="w", pady=(0, 8))

        # Fixed-height status area (3 lines) so a long status never changes the window size.
        status_area = ttk.Frame(root, height=52)
        self._status_area = status_area
        status_area.pack(fill="x")
        status_area.pack_propagate(False)
        self.status_bar = ttk.Label(status_area, text="Status: stopped", font=("Segoe UI", 9, "bold"),
                                    wraplength=wrap, justify="left")
        self.status_bar.pack(anchor="nw")

        self._build_side_panel(body)

    def _build_side_panel(self, body):
        """Right-hand pane (like v2rayN's server list): saved servers, connection graph, live log."""
        side = ttk.Frame(body, padding=(0, 16, 16, 16))
        side.grid(row=0, column=1, sticky="nsew")
        self._hist_state = {"open": True}
        self._log_state = {"open": True}

        # ---- servers
        ttk.Label(side, text="Servers", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        tbar = ttk.Frame(side)
        tbar.pack(fill="x", pady=(4, 4))
        for text, cmd in (("Paste link(s)", self._links_paste),
                          ("Remove", self._links_remove), ("\u25b2", lambda: self._links_move(-1)),
                          ("\u25bc", lambda: self._links_move(1))):
            ttk.Button(tbar, text=text, command=cmd, width=(3 if len(text) == 1 else None)).pack(side="left", padx=(0, 5))
        self._btn_testall = ttk.Button(tbar, text="Test all", command=self._links_test_all)
        self._btn_testall.pack(side="left", padx=(8, 5))
        ttk.Button(tbar, text="Sort", command=self._links_sort_speed, width=6).pack(side="left")
        wrap_t = ttk.Frame(side)
        wrap_t.pack(fill="both", expand=True)
        tree = ttk.Treeview(wrap_t, columns=("rank", "name", "proto", "addr", "latency", "status"),
                            show="headings", height=7, selectmode="browse")
        for col, text, width, anchor in (("rank", "#", 24, "center"), ("name", "Name", 110, "w"),
                                         ("proto", "Type", 52, "w"), ("addr", "Address", 110, "w"),
                                         ("latency", "Latency", 62, "e"), ("status", "Result", 78, "w")):
            tree.heading(col, text=text)
            tree.column(col, width=width, anchor=anchor, stretch=(col in ("name", "addr")))
        tsb = ttk.Scrollbar(wrap_t, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=tsb.set)
        tsb.pack(side="right", fill="y")
        tree.pack(side="left", fill="both", expand=True)
        tree.tag_configure("bad", foreground="#d9534f")
        tree.tag_configure("best", foreground="#2e9b4f")
        self._links_tree = tree
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Set as active", command=self._links_use_selected)
        menu.add_command(label="Paste links from clipboard", command=self._links_paste)
        menu.add_separator()
        menu.add_command(label="Rename...", command=self._links_rename)
        menu.add_command(label="Remove", command=self._links_remove)
        menu.add_command(label="Move up", command=lambda: self._links_move(-1))
        menu.add_command(label="Move down", command=lambda: self._links_move(1))
        menu.add_separator()
        menu.add_command(label="Test selected", command=lambda: self._links_test_all(only_selected=True))
        menu.add_command(label="Test all", command=self._links_test_all)
        menu.add_command(label="Sort by speed", command=self._links_sort_speed)

        def popup(event):
            row = tree.identify_row(event.y)
            if row:
                tree.selection_set(row)
            try:
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()

        tree.bind("<Button-3>", popup)
        tree.bind("<<TreeviewSelect>>", lambda e: self._links_on_select())
        tree.bind("<Double-1>", lambda e: self._links_use_selected())
        tree.bind("<Return>", lambda e: self._links_use_selected())
        tree.bind("<Delete>", lambda e: self._links_remove())
        tree.bind("<Control-v>", lambda e: self._links_paste())
        self._links_status_var = tk.StringVar(value="")
        ttk.Label(side, textvariable=self._links_status_var, font=("Segoe UI", 8), wraplength=SIDE_WIDTH - 20,
                  justify="left").pack(anchor="w", pady=(4, 0))
        fo_var = tk.BooleanVar(value=bool(self._settings.get("failover", True)))
        ttk.Checkbutton(side, text="Auto-switch server when the active one stops answering",
                        variable=fo_var, command=lambda: self._set_setting("failover", fo_var.get())
                        ).pack(anchor="w", pady=(2, 0))

        # ---- connection history
        ttk.Label(side, text="Voice ping", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(10, 2))
        self.hist_canvas = tk.Canvas(side, height=HIST_H, highlightthickness=1, bd=0)
        self.hist_canvas.pack(fill="x")
        self.hist_canvas.bind("<Configure>", lambda e: self._redraw_history())
        self.lbl_hist = ttk.Label(side, text="", font=("Segoe UI", 8), wraplength=SIDE_WIDTH - 20, justify="left")
        self.lbl_hist.pack(anchor="w", pady=(2, 0))

        # ---- live log (packed only when switched on in Settings)
        self._log_outer = ttk.Frame(side)
        ttk.Label(self._log_outer, text="Live log", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(10, 2))
        lb = self._log_outer
        row1 = ttk.Frame(lb)
        row1.pack(fill="x")
        ttk.Label(row1, text="Search:").pack(side="left")
        self._log_query = tk.StringVar()
        ttk.Entry(row1, textvariable=self._log_query).pack(side="left", fill="x", expand=True, padx=(6, 6))
        self._log_errors = tk.BooleanVar(value=False)
        self._log_discord = tk.BooleanVar(value=False)
        ttk.Button(row1, text="Clear", width=6, command=self._log_clear_view).pack(side="left")
        ttk.Button(row1, text="Copy", width=6, command=self._log_copy).pack(side="left", padx=(6, 0))
        row2 = ttk.Frame(lb)
        row2.pack(fill="x", pady=(2, 0))
        ttk.Checkbutton(row2, text="Errors only", variable=self._log_errors, command=self._log_refilter).pack(side="left")
        ttk.Checkbutton(row2, text="Discord only", variable=self._log_discord,
                        command=self._log_refilter).pack(side="left", padx=(10, 0))
        tf = ttk.Frame(lb)
        tf.pack(fill="both", expand=True, pady=(4, 0))
        self.log_text = tk.Text(tf, height=9, width=10, wrap="word", font=("Consolas", 8), state="disabled")
        log_sb = ttk.Scrollbar(tf, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_sb.set)
        log_sb.pack(side="right", fill="y")
        self.log_text.pack(side="left", fill="both", expand=True)
        self.lbl_logcount = ttk.Label(lb, text="", font=("Segoe UI", 8))
        self.lbl_logcount.pack(anchor="e")
        self.log_text.tag_configure("err", foreground="#d9534f")
        self.log_text.tag_configure("warn", foreground="#e0a030")
        self._log_query.trace_add("write", lambda *_a: self._log_schedule_refilter())

    def _fit_window(self):
        """Fixed window: narrow and tall, sized to fit every component. Not resizable."""
        try:
            self.update_idletasks()
            h = self.winfo_reqheight()
            if h < 200:                        # content not laid out yet - never shrink to a sliver
                return
            if self.winfo_width() != TOTAL_WIDTH or self.winfo_height() != h:
                x, y = self.winfo_x(), self.winfo_y()
                if self.state() == "normal" and self.winfo_ismapped():
                    self.geometry(f"{TOTAL_WIDTH}x{h}+{x}+{y}")   # keep the window where it is
                else:
                    self.geometry(f"{TOTAL_WIDTH}x{h}")
        except tk.TclError:
            pass

    def _clear_placeholder(self, _event=None):
        if self.input_box.get("1.0", "end-1c") == PLACEHOLDER:
            self.input_box.delete("1.0", "end")

    def _restore_placeholder(self, _event=None):
        if not self.input_box.get("1.0", "end-1c").strip():
            self.input_box.insert("1.0", PLACEHOLDER)

    # ---------------------------------------------- right-click edit menu

    def _attach_context_menu(self, widget: tk.Text):
        menu = tk.Menu(widget, tearoff=0)
        self._themed_menus.append(menu)
        menu.add_command(label="Cut", accelerator="Ctrl+X", command=lambda: self._ctx_cut(widget))
        menu.add_command(label="Copy", accelerator="Ctrl+C", command=lambda: self._ctx_copy(widget))
        menu.add_command(label="Paste", accelerator="Ctrl+V", command=lambda: self._ctx_paste(widget))
        menu.add_command(label="Delete", accelerator="Del", command=lambda: self._ctx_delete(widget))
        menu.add_separator()
        menu.add_command(label="Select All", accelerator="Ctrl+A", command=lambda: self._ctx_select_all(widget))

        def show(event):
            widget.focus_set()
            self._clear_placeholder()  # right-click on the grey hint text should not act on the hint
            has_sel = bool(widget.tag_ranges("sel"))
            try:
                has_clip = bool(self.clipboard_get())
            except tk.TclError:
                has_clip = False
            has_text = bool(widget.get("1.0", "end-1c"))
            menu.entryconfigure("Cut", state="normal" if has_sel else "disabled")
            menu.entryconfigure("Copy", state="normal" if has_sel else "disabled")
            menu.entryconfigure("Delete", state="normal" if has_sel else "disabled")
            menu.entryconfigure("Paste", state="normal" if has_clip else "disabled")
            menu.entryconfigure("Select All", state="normal" if has_text else "disabled")
            try:
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()
            return "break"

        widget.bind("<Button-3>", show)

    def _ctx_copy(self, widget: tk.Text):
        if widget.tag_ranges("sel"):
            self.clipboard_clear()
            self.clipboard_append(widget.get("sel.first", "sel.last"))

    def _ctx_delete(self, widget: tk.Text):
        if widget.tag_ranges("sel"):
            widget.delete("sel.first", "sel.last")

    def _ctx_cut(self, widget: tk.Text):
        self._ctx_copy(widget)
        self._ctx_delete(widget)

    def _ctx_paste(self, widget: tk.Text):
        try:
            text = self.clipboard_get()
        except tk.TclError:
            return
        self._clear_placeholder()
        self._ctx_delete(widget)
        widget.insert("insert", text)

    def _ctx_select_all(self, widget: tk.Text):
        widget.tag_add("sel", "1.0", "end-1c")
        widget.mark_set("insert", "end-1c")

    # ------------------------------------------------------------ status

    def refresh_all_status(self):
        for check in check_prerequisites():
            label = {
                "sing-box.exe": self.lbl_singbox,
                "wintun.dll": self.lbl_wintun,
                "Administrator": self.lbl_admin,
                "xray-core": self.lbl_xray,
            }[check["name"]]
            self._set_status(label, check["name"], check["ok"], check["detail"])
        try:
            if self._missing_components():
                if not self.btn_getfiles.winfo_ismapped():
                    self.btn_getfiles.pack(side="left", padx=(8, 0))
            elif self.btn_getfiles.winfo_ismapped():
                self.btn_getfiles.pack_forget()
        except tk.TclError:
            pass
        self._refresh_discord_status()

    def _refresh_discord_status(self):
        self._set_discord_label(get_running_discord_variant())

    def _set_discord_label(self, variant):
        self._set_status(self.lbl_discord, "Discord", variant is not None,
                         "running" if variant else "not running")

    def _status_tick(self):
        if self._exiting:
            return
        variant = get_running_discord_variant()
        self._set_discord_label(variant)
        try:
            self._watchdog_step(variant is not None)
            if self._settings.get("theme", "auto") == "auto" and windows_prefers_dark() != self._is_dark:
                self._apply_theme()  # Windows switched between light and dark
        except Exception as ex:
            self._append_log(f"--- watchdog error: {ex} ---")
        self.after(3000, self._status_tick)

    def _set_status(self, label: ttk.Label, name: str, ok: bool, detail: str):
        dot = "●" if ok else "○"
        label.configure(text=f"{dot} {name}: {detail}",
                        foreground=(self._pal["ok"] if ok else self._pal["warn"]))

    # ------------------------------------------------ watchdog / auto mode

    def _watchdog_step(self, discord_running: bool):
        # 1) xray-core (when it carries the connection) died on its own
        if (self._want_running and self._xray is not None and not self._xray.is_running
                and not self._recovering and not self._xray_swapping
                and self._state in ("running", "starting")):
            self._auto_recover("xray-core stopped unexpectedly")
            return

        # 2) smart auto-start: follow Discord
        if not self._settings.get("auto_mode") or self._cleanup_pending:
            return
        now = time.monotonic()
        if discord_running:
            self._discord_gone_since = None
            if not self._want_running and not self._auto_suppressed:
                self._append_log("--- auto mode: Discord detected, starting the proxy ---")
                self.start_proxy(auto=True)
        else:
            self._auto_suppressed = False
            if self._want_running and self._auto_started:
                if self._discord_gone_since is None:
                    self._discord_gone_since = now
                elif now - self._discord_gone_since >= 15:  # grace: Discord restarts itself for updates
                    self._discord_gone_since = None
                    self._append_log("--- auto mode: Discord closed, stopping the proxy ---")
                    self._notify("Discord closed", "Proxy stopped.")
                    self.stop_proxy()
                    self._auto_suppressed = False

    def _auto_fail(self, message: str):
        self._auto_suppressed = True  # don't retry every 3 s; resets when Discord closes
        self._append_log(f"--- auto mode: not started - {message} ---")
        self.status_bar.configure(text="Status: auto start failed")
        self._notify("Auto mode could not start the proxy", message, "warning")

    def _restart_elevated(self):
        if messagebox.askyesno(
            "Discord Proxy",
            "Restart as Administrator?",
        ):
            if self._single:
                self._single.release()  # so the elevated copy is not mistaken for a second instance
            if relaunch_as_admin():
                self._exiting = True
                if self._tray:
                    self._tray.stop()
                self._manager.stop()
                if self._xray:
                    self._xray.stop()
                self.destroy()
                sys.exit(0)
            else:
                if self._single and self._single.acquire():
                    self._single.listen(lambda: self._event_queue.put(("tray", "show")))
                messagebox.showerror("Discord Proxy", "Could not restart as Administrator.")

    # ------------------------------------------------------------- start

    def _link_text(self) -> str:
        text = self.input_box.get("1.0", "end-1c")
        if text.strip() and text.strip() != PLACEHOLDER.strip():
            return text
        # nothing chosen yet: use the highlighted server of the list, else the first saved one
        tree = getattr(self, "_links_tree", None)
        links = self._saved_links() if hasattr(self, "_settings") else []
        try:
            sel = tree.selection() if tree is not None else ()
            if sel and int(sel[0]) < len(links):
                return links[int(sel[0])]["link"]
        except (tk.TclError, ValueError):
            pass
        return links[0]["link"] if links else ""

    def start_proxy(self, auto: bool = False):
        if self._manager.is_running or self._want_running:
            if not auto:
                self.status_bar.configure(text="Status: already running")
            return
        if self._cleanup_pending:
            self.status_bar.configure(text="Status: cleaning up - try again")
            return

        missing = [c for c in self._missing_components() if COMPONENTS[c]["required"]]
        if missing:
            if auto:
                self._auto_fail(" / ".join(COMPONENTS[c]["file"] for c in missing) + " not found")
                return
            self._offer_download(preselect=missing, then=lambda: self.start_proxy())
            return

        if not is_admin():
            if auto:
                self._auto_fail("Administrator required")
                return
            if messagebox.askyesno(
                "Discord Proxy",
                "Not running as Administrator. Restart as Administrator now?",
            ):
                self._restart_elevated()
                return

        text = self._link_text()
        if auto and not text.strip():
            text = (self._settings.get("link") or "")
            if not text.strip():
                self._auto_fail("No saved proxy link")
                return
        if not self._prepare_chain(text, interactive=not auto):
            if auto:
                self._auto_suppressed = True
            return

        self._last_text = text
        if text.strip() and self._settings.get("link") != text.strip():
            self._settings["link"] = text.strip()  # remembered for auto mode and the next launch
            save_settings(self._settings)
        self._want_running = True
        self._force_all = False
        self._voice_deadline = None
        self._voice_return_gen += 1
        self._recovering = False
        self._auto_started = auto
        self._retry = 0
        self._recover_times = []
        self._health_lost = False
        self._health_restarted = False
        self._announce_restored = False
        self._voice_status = VoiceStatus()
        self._voice_last = ("idle", 0.0, 0.0, 0)
        self._ping_ms = None
        self._guard_notified = False
        self._link_failed_at = {}
        self._voiceq = None
        self._begin_launch()

    def _log_link_diagnostics(self, outbound: dict) -> None:
        """Ignored link parameters, core versions vs. needed features, link-storage state."""
        ign = outbound.get("_ignored") or []
        if ign:
            self._append_log("--- WARNING: link parameters ignored (not supported by this tool): "
                             + ", ".join(ign) + " ---")
        try:
            info, warns = preflight_info(outbound)
        except Exception as ex:
            info, warns = "", [f"version check failed: {ex}"]
        if info:
            self._append_log(f"--- {info} ---")
        for w in warns:
            self._append_log(f"--- WARNING: {w} ---")
        if os.name == "nt" and _LINK_STATE["failed"]:
            self._append_log("--- WARNING: the saved link could not be decrypted (it was saved by another "
                             "Windows account or PC) - paste it again ---")
        elif os.name == "nt" and not _LINK_STATE["encrypted"]:
            self._append_log("--- WARNING: could not encrypt the saved link (Windows DPAPI unavailable) - "
                             "it is stored in plain text in dp_data\\settings.json ---")

    def _prepare_chain(self, text: str, interactive: bool) -> bool:
        """Parses the link, starts xray-core if needed and writes sing-box's
        config. Used for the first start and again for every auto-recovery."""
        outbound, err = parse_proxy_link(text)
        if err:
            if interactive:
                messagebox.showerror("Discord Proxy - Invalid Configuration", err)
            else:
                self._append_log(f"--- invalid configuration: {err} ---")
                self.status_bar.configure(text="Status: invalid proxy configuration")
            return False
        if interactive or getattr(self, "_diag_key", None) != text:
            self._diag_key = text
            self._log_link_diagnostics(outbound)
        try:
            # For XHTTP links this starts a local xray-core instance and swaps in a
            # plain loopback SOCKS outbound for sing-box; otherwise `outbound` passes
            # through unchanged. _on_log_bg (queue-based) because xray's reader thread
            # calls it and Tk widgets may only be touched from the main thread.
            effective_outbound, xray_mgr = start_xray_chain_if_needed(
                outbound, self._on_log_bg, self._selected_core())
        except Exception as ex:
            if interactive and isinstance(ex, FileNotFoundError) and not os.path.isfile(xray_exe_path()):
                self.status_bar.configure(text="Status: xray.exe is missing")
                self._offer_download(preselect=["xray"], then=lambda: self.start_proxy())
                return False
            if interactive:
                messagebox.showerror("Discord Proxy", str(ex))
                self.status_bar.configure(text="Status: error")
            else:
                self._append_log(f"--- could not start the proxy core: {ex} ---")
            return False
        self._xray = xray_mgr
        self._xray_port = effective_outbound.get("server_port") if xray_mgr else None

        api = {"port": _free_local_port(), "secret": secrets.token_hex(16)}
        if self._settings.get("voice_probe", True):
            api["probe_port"] = _free_udp_port()
        _SECRETS.add(api["secret"])
        config = build_singbox_config(effective_outbound, api, self._capture_settings())
        os.makedirs(config_dir(), exist_ok=True)
        with open(generated_config_path(), "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        err = validate_singbox_config(generated_config_path())  # noqa
        if err:
            msg = "sing-box rejected the generated configuration (sing-box check):\n\n" + mask_secrets(err)[:1500]
            if self._xray:
                self._xray.stop()
                self._xray = None
            if interactive:
                messagebox.showerror("Discord Proxy - Configuration check failed", msg)
            else:
                self._append_log("--- " + msg.replace("\n\n", ": ", 1) + " ---")
            self.status_bar.configure(text="Status: configuration check failed")
            return False
        self._api = api
        return True

    # ----------------------------------------------------- launch / retry

    # Messages sing-box prints when Windows has not finished releasing the
    # previous TUN adapter (or a stale one is still registered).
    _TUN_BUSY_MARKERS = (
        "device is not ready for use",
        "open interface take too much time",
        "configure tun interface",
        "file already exists",
    )

    def _begin_launch(self, extra_delay: float = 0.0):
        """Removes any stale 'DiscordProxy' adapter in the background, then
        starts sing-box - without freezing the window."""
        self._launch_token += 1
        token = self._launch_token
        self.btn_start.state(["disabled"])
        self.btn_stop.state(["!disabled"])
        self.core_combo.configure(state="disabled")
        self.status_bar.configure(text="Status: starting...")

        def worker():
            try:
                if os.name == "nt":
                    remove_discord_tun_adapter(force=True)
                if extra_delay:
                    time.sleep(extra_delay)
            finally:
                self._event_queue.put(("launch", token))

        threading.Thread(target=worker, daemon=True).start()

    def _do_launch(self, token: int):
        if token != self._launch_token or self._exiting:
            return  # Stop was pressed (or the app is closing) while waiting
        self._proc_token = token
        self._recovering = False
        self._launch_time = time.monotonic()
        self._log_start = self._log_total
        self._health_fail = 0
        self._append_log(f"--- starting sing-box with {generated_config_path()} ---")
        try:
            self._manager.start(generated_config_path())
        except Exception as ex:
            messagebox.showerror("Discord Proxy", str(ex))
            self._want_running = False
            if self._auto_started:
                self._auto_suppressed = True
            self.status_bar.configure(text="Status: error")
            if self._xray:
                self._xray.stop()
                self._xray = None
            self.btn_start.state(["!disabled"])
            self.btn_stop.state(["disabled"])
            self.core_combo.configure(state="readonly")
            self._set_proxy_state("stopped")
            return

        api = self._api or {"port": _free_local_port(), "secret": secrets.token_hex(16)}
        self._monitor = TrafficMonitor(api["port"], api["secret"],
                                       lambda u, d: self._event_queue.put(("stats", (u, d))),
                                       self._on_log_bg)
        self._monitor.start()
        self._health = HealthMonitor(api["port"], api["secret"],
                                     lambda r, t=token: self._event_queue.put(("health", (t, r))))
        self._health.start()
        self._voice_wd = VoiceStallWatchdog(api["port"], api["secret"], self._on_log_bg, self._voice_status,
                                            lambda st: self._event_queue.put(("voicestat", st)))
        self._voice_wd.start()
        if api.get("probe_port"):
            self._voice_probe = VoiceQualityProbe(api["probe_port"], self._voice_status,
                                                  lambda q: self._event_queue.put(("voiceq", q)))
            self._voice_probe.start()
        self._active_core = "Xray-core" if self._xray else "sing-box"
        self.status_bar.configure(
            text=f"Status: running via {self._active_core}")
        self._set_proxy_state("starting")
        self.after(5000, lambda t=token: self._confirm_started(t))

    def _confirm_started(self, token: int):
        """5 s after launch: still alive => it really is connected."""
        if (token != self._proc_token or token != self._launch_token or self._exiting
                or not self._want_running or not self._manager.is_running):
            return
        if self._health_lost:
            return  # the health check will announce the recovery
        self._set_proxy_state("running")
        if self._announce_restored:
            self._announce_restored = False
            self._notify("Proxy restored", f"Running via {self._active_core}.")
        elif self._auto_started:
            self._notify("Discord detected - proxy started", f"Running via {self._active_core}.")
        else:
            self._notify("Proxy connected", f"Running via {self._active_core}.")

    def _recent_lines(self) -> list:
        n = self._log_total - self._log_start
        return list(self._log_lines)[-n:] if n > 0 else []

    def _report_failure(self):
        """Plain-language message for a proxy that could not start / keep running."""
        info = explain_failure(self._recent_lines())
        if info:
            title, advice = _SHORT_FAIL.get(info[0], (info[1], ""))
        else:
            title, advice = "sing-box stopped", "See Export Log."
        self.status_bar.configure(text=f"Status: {title}. {advice}")
        self._notify("Discord Proxy stopped", f"{title}. {advice}", "error")
        try:
            visible = self.state() == "normal"
        except tk.TclError:
            visible = False
        if visible:
            messagebox.showerror("Discord Proxy", f"{title}\n{advice}")

    # --------------------------------------------------- recovery / health

    def _auto_recover(self, reason: str):
        """The proxy died or stopped answering: restart the whole chain, but
        never more than RECOVER_MAX times per RECOVER_WINDOW_S."""
        if self._exiting or not self._want_running:
            return
        now = time.monotonic()
        self._recover_times = [t for t in self._recover_times if now - t < RECOVER_WINDOW_S]
        if len(self._recover_times) >= RECOVER_MAX:
            self._give_up(reason)
            return
        self._recover_times.append(now)
        n = len(self._recover_times)
        if self._soft_restart_xray(reason, n):
            return
        self._append_log(f"--- auto-recover: {reason} - restarting ({n}/{RECOVER_MAX}) ---")
        self.status_bar.configure(text=f"Status: {short_reason(reason)} - restarting ({n}/{RECOVER_MAX})")
        self._set_proxy_state("retrying")
        self._notify("Proxy lost - restarting", f"{short_reason(reason)} ({n}/{RECOVER_MAX})", "warning")
        self._announce_restored = True
        self._restart_chain(delay=min(2 * n, 10))

    def _soft_restart_xray(self, reason: str, n: int) -> bool:
        """Restart ONLY xray-core on its old loopback port. sing-box, the TUN adapter
        and Discord's sockets stay untouched, so a running voice call just gets a
        fresh proxy-side session instead of a dead one. Returns False when this is
        not possible (no xray in use, sing-box itself gone) -> full restart."""
        if (self._xray is None or self._xray_port is None or not self._manager.is_running
                or self._xray_swapping or not self._last_text):
            return False
        outbound, err = parse_proxy_link(self._last_text)
        if err or outbound is None:
            return False
        self._xray_swapping = True
        self._append_log(f"--- auto-recover: {reason} - restarting only xray-core, TUN stays up ({n}/{RECOVER_MAX}) ---")
        old, token = self._xray, self._launch_token

        def worker():
            try:
                old.stop()
                time.sleep(1.0)
                mgr = XrayManager(on_log=lambda l: self._on_log_bg("[xray-core] " + l), on_exit=lambda c: None)
                cfg = build_xray_config(outbound, self._xray_port)
                with open(xray_config_path(), "w", encoding="utf-8") as f:
                    json.dump(cfg, f, indent=2)
                mgr.start(xray_config_path())
                if token == self._launch_token and self._want_running:
                    self._xray = mgr
                else:
                    mgr.stop()
                self._on_log_bg("--- xray-core restarted; existing Discord voice flows will be re-opened automatically ---")
            except Exception as ex:
                self._on_log_bg(f"--- soft xray restart failed: {ex} ---")
            finally:
                self._health_fail = 0
                self._xray_swapping = False

        threading.Thread(target=worker, daemon=True).start()
        return True

    def _restart_chain(self, delay: float):
        ks_thread = self._ks_engage("proxy chain restarting")   # armed runs only; before the TUN goes away
        self._recovering = True
        self._launch_token += 1
        token = self._launch_token
        self._finish_monitor()
        self.btn_start.state(["disabled"])
        self.btn_stop.state(["!disabled"])

        def worker():
            try:
                if ks_thread is not None:
                    ks_thread.join(timeout=10)         # Discord is firewalled before sing-box stops
                self._manager.stop()
                x, self._xray = self._xray, None
                if x:
                    x.stop()
                time.sleep(delay)
            finally:
                self._event_queue.put(("rechain", token))

        threading.Thread(target=worker, daemon=True).start()

    def _do_rechain(self, token: int):
        if token != self._launch_token or self._exiting or not self._want_running:
            return
        if not self._prepare_chain(self._last_text, interactive=False):
            self._give_up("The proxy settings could not be applied")
            return
        self._begin_launch()

    def _give_up(self, reason: str):
        self._ks_engage("auto-recover gave up")
        self._want_running = False
        self._recovering = False
        if self._auto_started:
            self._auto_suppressed = True
        self._append_log(f"--- auto-recover gave up: {reason} ---")
        self._stop_everything()
        info = explain_failure(self._recent_lines())
        extra = _SHORT_FAIL.get(info[0], ("", ""))[1] if info else "See Export Log."
        self.status_bar.configure(text=f"Status: stopped - {short_reason(reason)}"
                                       + (" - Discord blocked (kill switch)" if self._ks_engaged else ""))
        self._notify("Proxy stopped", f"{short_reason(reason)}. {extra}".strip(), "error")

    def _on_health(self, token: int, result):
        if token != self._proc_token or not self._want_running or self._recovering:
            return
        verdict = result["verdict"] if isinstance(result, dict) else result
        if verdict == "unsupported":
            if self._health:
                self._health.stop()
            self._append_log("--- health check not available in this sing-box build; relying on process watch only ---")
            return
        if verdict == "ok":
            self._health_fail = 0
            self._health_restarted = False
            self._guard_notified = False
            if self._ks_engaged:
                self._ks_release("proxy verified - Discord unblocked")
            if isinstance(result, dict):
                if result.get("median") is not None:
                    self._ping_ms = int(result["median"])
                    self._refresh_voice_label()

                note = result.get("note") or ""
                if note and note != self._last_health_note:
                    self._append_log(f"--- health check: {note} ---")
                self._last_health_note = note
            if self._health_lost:
                self._health_lost = False
                self._set_proxy_state("running")
                self.status_bar.configure(
                    text=f"Status: running via {self._active_core}")
                self._append_log("--- health check: the proxy server is answering again (no restart was needed) ---")
            return
        if verdict == "fail":
            self._health_fail += 1
            self._ping_ms = -1
            self._refresh_voice_label()
            if self._health_fail >= HEALTH_FAILS_NOTICE and not self._health_lost:
                # Poor connection: only report it (status bar + log). No popup, no restart -
                # sing-box/xray keep the existing flows and recover by themselves.
                self._health_lost = True
                self._set_proxy_state("retrying")
                self.status_bar.configure(text="Status: weak connection")
                self._append_log("--- health check: weak/no answer from the proxy server (not restarting yet) ---")
            if self._health_fail >= FAILOVER_FAILS and self._try_failover("the proxy server stopped answering"):
                return
            if self._health_fail >= HEALTH_FAILS_RESTART and not self._health_restarted:
                if self._voice_call_active():
                    # Mid-call guard: a restart would tear down the TUN and every UDP flow and kill
                    # the call. Only a dead process (handled elsewhere) restarts during a call.
                    if not self._guard_notified:
                        self._guard_notified = True
                        self._append_log("--- mid-call guard: the proxy server has not answered for several minutes, "
                                         "but a voice call is active - NOT restarting. It restarts only if the "
                                         "process itself dies, or after the call if the server is still silent ---")
                        self.status_bar.configure(
                            text="Status: server silent - call active")
                        self._notify("Voice call active - not restarting",
                                     "Server silent - restart postponed.",
                                     "warning")
                    return
                self._health_restarted = True  # one restart per outage; then just keep watching
                self._auto_recover("The proxy server has not answered for several minutes")

    # ------------------------------------------------ tray status / notices

    def _set_proxy_state(self, state: str):
        self._state = state
        tips = {"stopped": "Discord Proxy - stopped", "starting": "Discord Proxy - starting...",
                "running": "Discord Proxy - running", "retrying": "Discord Proxy - reconnecting..."}
        icon_state = state if state in ("running", "stopped") else "busy"
        if self._tray:
            self._tray.set_state(state, icon_state, tips.get(state, "Discord Proxy"))
        self._apply_window_icon(icon_state)

    def _notify(self, title: str, text: str, kind: str = "info"):
        if not self._settings.get("notifications", True):
            return
        if self._tray and self._tray.active:
            self._tray.notify(title, text, kind)

    def _start_tray(self):
        if self._tray and not self._tray.active:
            self._tray.start()
        self._set_proxy_state(self._state)

    def _apply_window_icon(self, state: str = "stopped"):
        state = "plain"  # main logo stays blue; only the tray icon changes colour
        if getattr(self, "_window_icon_state", None) == state:
            return
        try:
            png = png_bytes(64, render_icon_pixels(64, state))
            img = tk.PhotoImage(data=base64.b64encode(png))
            self.iconphoto(True, img)
            self._icon_ref = img  # Tk keeps no reference of its own
            self._window_icon_state = state
        except Exception:
            pass

    # ------------------------------------------------- startup cleanup

    def _begin_startup_cleanup(self):
        if os.name != "nt" or not is_admin():
            return
        self._cleanup_pending = True

        def worker():
            try:
                found = cleanup_leftovers()
            except Exception:
                found = []
            self._event_queue.put(("cleanup", found))

        threading.Thread(target=worker, daemon=True).start()

    def _recent_log_text(self) -> str:
        n = self._log_total - self._log_start
        if n <= 0:
            return ""
        return "\n".join(list(self._log_lines)[-n:]).lower()

    def _tun_busy_in_recent_log(self) -> bool:
        text = self._recent_log_text()
        return any(m in text for m in self._TUN_BUSY_MARKERS)

    def _should_retry_launch(self, code: int) -> bool:
        return (code != 0 and not self._exiting and self._retry < 3
                and self._proc_token == self._launch_token      # not a user Stop
                and time.monotonic() - self._launch_time < 60   # failed right at startup
                and self._tun_busy_in_recent_log())

    # -------------------------------------------------------------- stop

    def test_proxy(self):
        text = self._link_text()
        outbound, err = parse_proxy_link(text) if text.strip() else (None, None)
        if text.strip() and err:
            messagebox.showerror("Discord Proxy - Invalid Configuration", err)
            return

        # The proxy is running and the box holds the same link (or is empty): test the LIVE
        # connection through sing-box's own stats API. No second sing-box/xray is started and
        # nothing is restarted, so Discord / a voice call keep running undisturbed.
        live = (self._manager.is_running and self._api is not None and not self._recovering
                and not self._xray_swapping and self._state in ("running", "starting", "retrying")
                and (not text.strip() or text.strip() == (self._last_text or "").strip()))
        if live:
            self.btn_test.state(["disabled"])
            self.status_bar.configure(text="Status: testing the live connection...")
            self._append_log("--- testing the LIVE connection through the running proxy "
                             "(nothing is restarted or interrupted) ---")
            threading.Thread(target=self._live_test_worker, args=(dict(self._api),), daemon=True).start()
            return

        if outbound is None:
            _o, err = parse_proxy_link(text)
            messagebox.showerror("Discord Proxy - Invalid Configuration", err)
            return
        if not os.path.isfile(singbox_exe_path()):
            messagebox.showwarning("Discord Proxy", "sing-box.exe not found.")
            return
        self._log_link_diagnostics(outbound)
        self.btn_test.state(["disabled"])
        self.status_bar.configure(text="Status: testing...")
        bypass = self._manager.is_running      # real proxy is up: keep the test completely separate from it
        self._append_log("--- testing proxy: fetching discord.com through it (up to ~20s)"
                         + (" - separate test instance, the running proxy is not touched" if bypass else "") + " ---")
        threading.Thread(target=self._test_worker, args=(outbound, self._selected_core(), bypass),
                         daemon=True).start()

    def _live_test_worker(self, api: dict):
        result = (False, "The test did not complete.")
        try:
            ok, ms, err = api_delay_test(api["port"], api["secret"], HealthMonitor.GATEWAY_URL, 15000)
            if ok:
                result = (True, f"discord.com answered through the running proxy in {ms} ms\n"
                                "(live test - the connection was not interrupted)")
            else:
                ok2, ms2, err2 = api_delay_test(api["port"], api["secret"], HealthMonitor.CONTROL_URL, 10000)
                if ok2:
                    result = (False, f"The proxy server answers ({ms2} ms to a neutral test address) but "
                                     f"Discord's gateway did not answer through it:\n{err}")
                else:
                    result = (False, f"No answer through the running proxy:\n{err or err2}")
        except Exception as ex:
            result = (False, f"The live test failed: {ex}")
        self._event_queue.put(("verdict", result))

    def _test_worker(self, outbound, core, bypass_tun=False):
        import socket, urllib.request, urllib.error
        log = lambda m: self._event_queue.put(("log", m))
        result = (False, "The test did not complete.")
        mgr = xray_mgr = None
        test_cfg = os.path.join(config_dir(), "test.json")
        try:
            try:
                # Same core selection as the real run; Xray gets a temporary local instance
                # (own config file + own port) for this test only - never the live xray.json.
                outbound, xray_mgr = start_xray_chain_if_needed(outbound, log, core, loglevel="info",
                                                                config_path=xray_test_config_path())
                with socket.socket() as sk:
                    sk.bind(("127.0.0.1", 0))
                    port = sk.getsockname()[1]
                os.makedirs(config_dir(), exist_ok=True)
                with open(test_cfg, "w", encoding="utf-8") as f:
                    json.dump(build_test_config(outbound, port, bypass_tun), f, indent=2)
                mgr = SingBoxManager(on_log=lambda l: log("[test] " + l), on_exit=lambda c: None, cleanup_adapter=False)
                mgr.start(test_cfg)
                time.sleep(2.5)
            except Exception as ex:
                result = (False, f"Could not start the test: {ex}")
            else:
                proxy = f"http://127.0.0.1:{port}"
                ctx, verified = make_ssl_context()
                if not verified:
                    log("--- test: no usable certificate store found on this PC - the TLS certificate is NOT "
                        "verified in this test (it only checks that the tunnel carries traffic) ---")
                opener = urllib.request.build_opener(
                    urllib.request.ProxyHandler({"http": proxy, "https": proxy}),
                    urllib.request.HTTPSHandler(context=ctx))
                # Discord's CDN answers the default "Python-urllib" User-Agent with a 403,
                # so send a browser-like one, and treat ANY HTTP response from discord.com
                # as proof the tunnel works (a proxy-side failure shows up as a connection
                # or TLS error, never as an HTTP status from Discord).
                req = urllib.request.Request(
                    "https://discord.com/api/v9/gateway",
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                                           "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"})
                t0 = time.time()
                try:
                    with opener.open(req, timeout=15) as r:
                        code = r.status
                    result = (True, f"discord.com answered HTTP {code} in {int((time.time() - t0) * 1000)} ms")
                except urllib.error.HTTPError as ex:
                    result = (True, f"discord.com answered HTTP {ex.code} in {int((time.time() - t0) * 1000)} ms")
                except Exception as ex:
                    result = (False, self._explain_failure(ex))
                    reason = getattr(ex, "reason", ex)
                    log(f"--- test error detail: {type(reason).__name__}: errno={getattr(reason, 'errno', None)} "
                        f"filename={getattr(reason, 'filename', None)!r} ---")
                    for line in ssl_diagnostics():
                        log("--- " + line + " ---")
        finally:
            if mgr:
                mgr.stop()
            if xray_mgr:
                xray_mgr.stop()
            for path in (test_cfg, xray_test_config_path()):   # credentials in plain text: remove right away
                try:
                    if os.path.exists(path):
                        os.remove(path)
                except OSError:
                    pass
        self._event_queue.put(("verdict", result))

    @staticmethod
    def _explain_failure(ex) -> str:
        s = str(ex)
        low = s.lower()
        reason = getattr(ex, "reason", ex)
        if isinstance(reason, FileNotFoundError) or "[errno 2]" in low:
            fname = getattr(reason, "filename", None)
            return ("Python could not find a file it needs for the secure (HTTPS) connection"
                    + (f" ({fname})" if fname else "")
                    + " - usually a leftover SSL_CERT_FILE / SSLKEYLOGFILE environment variable pointing at "
                      "something that no longer exists. Details are in Export Log. "
                    + f"[{s}]")
        if "timed out" in low:
            return f"Timed out - the proxy server did not answer (wrong address/port, blocked, or server down). [{s}]"
        if "eof" in low or "forcibly closed" in low or "reset" in low:
            return ("The proxy server closed the connection - check UUID / path / host / SNI / encryption / "
                    f"extra in the link, or try the other proxy core. [{s}]")
        return s

    def _show_verdict(self, ok: bool, msg: str):
        self.btn_test.state(["!disabled"])
        banner = "✔  PROXY IS WORKING" if ok else "✘  PROXY IS NOT WORKING"
        self._append_log("=" * 60)
        self._append_log(f"TEST RESULT: {banner}")
        self._append_log(f"  {msg}")
        self._append_log("=" * 60)
        if self._manager.is_running:
            self.status_bar.configure(text=f"Status: running via {self._active_core} - test {'OK' if ok else 'FAILED'}")
        else:
            self.status_bar.configure(text=f"Status: stopped - test {'OK' if ok else 'FAILED'}")
        if ok:
            messagebox.showinfo("Discord Proxy - Test", f"{banner}\n\n{msg}")
        else:
            messagebox.showerror("Discord Proxy - Test", f"{banner}\n\n{msg}")

    def _stop_everything(self):
        """Stops sing-box, xray-core and the monitors, and resets the UI."""
        self._launch_token += 1  # any pending launch / stale exit event is now ignored
        self._finish_monitor()
        self._manager.stop()
        if self._xray:
            self._xray.stop()
            self._xray = None
        flush_dns()
        scrub_runtime_configs(include_tests=False)
        self.btn_start.state(["!disabled"])
        self.btn_stop.state(["disabled"])
        self.core_combo.configure(state="readonly")
        self._set_proxy_state("stopped")

    def retry_connection(self):
        """Retry button. Stopped / failed -> same as Start. Running (or weak / stuck) -> a clean
        full restart of the chain with the link that is currently in the box, counters reset."""
        if self._exiting:
            return
        if self._cleanup_pending:
            self.status_bar.configure(text="Status: cleaning up - try again")
            return
        if self._recovering:
            self.status_bar.configure(text="Status: already reconnecting...")
            return
        if not self._want_running:
            self._auto_suppressed = False
            self._append_log("--- retry: starting the proxy ---")
            self.start_proxy()
            return
        text = self._link_text().strip() or (self._last_text or "").strip()
        if not text:
            messagebox.showwarning("Discord Proxy", "No proxy link to retry with.")
            return
        _ob, err = parse_proxy_link(text)
        if err:
            messagebox.showerror("Discord Proxy - Invalid Configuration", err)
            return
        if self._voice_call_active() and not messagebox.askyesno(
                "Discord Proxy", "A Discord voice call is active - retrying drops it for a few seconds.\n\nRetry anyway?"):
            return
        self._last_text = text
        if self._settings.get("link") != text:
            self._settings["link"] = text
            save_settings(self._settings)
        self._recover_times = []
        self._retry = 0
        self._health_fail = 0
        self._health_lost = False
        self._health_restarted = False
        self._guard_notified = False
        self._ping_ms = None
        self._announce_restored = True
        self._append_log("--- retry: restarting the connection (manual) ---")
        self.status_bar.configure(text="Status: retrying connection...")
        self._set_proxy_state("retrying")
        self._restart_chain(delay=1.0)

    def close_discord(self):
        """Close Discord button: force-closes every Discord process (as listed in Task Manager)."""
        if self._discord_closing or self._exiting:
            return
        if self._voice_call_active() and not messagebox.askyesno(
                "Discord Proxy", "A Discord voice call is active.\n\nClose Discord completely anyway?"):
            return
        self._discord_closing = True
        self.btn_close_discord.state(["disabled"])
        self.status_bar.configure(text="Status: closing Discord...")
        self._append_log("--- closing Discord (all Discord processes) ---")

        def worker():
            try:
                result = close_discord_processes()
            except Exception:
                result = (0, -1)
            self._event_queue.put(("discord_closed", result))

        threading.Thread(target=worker, daemon=True).start()

    def _on_discord_closed(self, payload):
        closed, left = payload
        self._discord_closing = False
        try:
            self.btn_close_discord.state(["!disabled"])
        except tk.TclError:
            return
        self._refresh_discord_status()
        if left and left > 0:
            self._append_log(f"--- Discord: {left} process(es) could not be closed ---")
            self.status_bar.configure(text=f"Status: {left} Discord process(es) still running - "
                                           "try again or run as Administrator")
        elif closed == 0:
            self._append_log("--- Discord was not running ---")
            self.status_bar.configure(text="Status: Discord was not running")
        else:
            n = "all" if closed < 0 else str(closed)
            self._append_log(f"--- Discord closed completely ({n} process(es)) ---")
            self.status_bar.configure(text="Status: Discord closed completely")

    # ---- kill switch

    def _ks_armed(self) -> bool:
        """Active only for a normal run: not while ranges are still being learned / everything is
        captured as a fallback, and only if the setting is on."""
        return (os.name == "nt" and bool(self._settings.get("kill_switch", True))
                and self._want_running and not self._learning_run)

    def _ks_run(self, engage: bool):
        self._ks_gen += 1
        gen = self._ks_gen

        def worker():
            with _KS_LOCK:
                if gen != self._ks_gen:         # a newer engage/release superseded this one
                    return
                if engage:
                    n = killswitch_engage()
                    msg = (f"--- kill switch: Discord is blocked ({n} firewall rule(s)) ---" if n
                           else "--- kill switch: no Discord program found to block (needs Administrator) ---")
                else:
                    killswitch_release()
                    msg = "--- kill switch: Discord unblocked ---"
            self._event_queue.put(("log", msg))

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        return t

    def _ks_engage(self, reason: str):
        """Blocks Discord until the proxy is verified again. Returns the worker thread (or None)."""
        if self._ks_engaged or not self._ks_armed():
            return None
        self._ks_engaged = True
        self._append_log(f"--- kill switch: {reason} - blocking Discord until the proxy answers again ---")
        self._notify("Kill switch active", "Proxy down - Discord is blocked so it cannot connect directly.",
                     "warning")
        return self._ks_run(True)

    def _ks_release(self, why: str = "", force: bool = False):
        if not self._ks_engaged and not force:
            return
        self._ks_engaged = False
        if why:
            self._append_log(f"--- kill switch: {why} ---")
        self._ks_run(False)

    def _ks_release_now(self):
        """Synchronous release (used on exit so Discord is never left blocked)."""
        self._ks_engaged = False
        self._ks_gen += 1
        with _KS_LOCK:
            killswitch_release()

    def _ks_startup_check(self):
        """Rules left by a previous run (crash while the proxy was down): keep them only while the
        kill switch is on - they are lifted as soon as the proxy is verified."""
        if os.name != "nt" or not is_admin():
            return

        def worker():
            if not killswitch_rules_exist():
                return
            if self._settings.get("kill_switch", True):
                self._ks_engaged = True
                self._event_queue.put(("log", "--- kill switch: still active from the previous run - Discord is "
                                              "unblocked once the proxy answers (Start), or from Settings > Network ---"))
            else:
                with _KS_LOCK:
                    killswitch_release()
                self._event_queue.put(("log", "--- kill switch: removed leftover rules (kill switch is off) ---"))

        threading.Thread(target=worker, daemon=True).start()

    def stop_proxy(self):
        self._want_running = False
        self._recovering = False
        self._health_lost = False
        self._auto_suppressed = True  # a manual Stop must not be undone by auto mode while Discord is open
        self._ks_release("proxy stopped by you")
        self._stop_everything()
        self.status_bar.configure(text="Status: stopped")
        self._append_log("--- stop requested ---")

    # ------------------------------------------------- core / traffic / log

    def _selected_core(self) -> str:
        return CORE_CHOICES.get(self.core_var.get(), "auto")

    def _on_core_changed(self, _event=None):
        self._settings["core"] = self._selected_core()
        save_settings(self._settings)

    @staticmethod
    def _fmt_rate(bps: float) -> str:
        return f"{bps / 1024:.1f} kB/s"

    def _voice_text(self, state: str, up: float, down: float, resets: int) -> str:
        if self._ping_ms is None:
            ping = ""
        elif self._ping_ms < 0:
            ping = "   proxy: no answer"
        else:
            ping = f"   proxy {self._ping_ms} ms"
        tail = f"{ping}   reset {resets}×"
        if state == "idle":
            return f"idle (no voice call){tail}"
        label = {"ok": "OK", "stalled": "STALLED", "recovering": "RECOVERING"}.get(state, state)
        return f"{label}   ↑ {self._fmt_rate(up)} ↓ {self._fmt_rate(down)}{tail}"

    def _refresh_voice_label(self):
        state = self._voice_last[0]
        pal = getattr(self, "_pal", {}) or {}
        color = {"ok": "#2e9b4f", "stalled": "#d9534f", "recovering": "#e0a030"}.get(state, pal.get("muted", "#777777"))
        try:
            self.lbl_voice.configure(text=self._voice_text(*self._voice_last), foreground=color)
        except tk.TclError:
            pass

    def _voice_call_active(self) -> bool:
        """A Discord voice UDP flow exists (or did a moment ago) - mid-call guard."""
        return self._voice_status.in_call()

    @staticmethod
    def _traffic_text(up: int, down: int) -> str:
        return f"↑ Upload {fmt_bytes(up)}   ↓ Download {fmt_bytes(down)}   Total {fmt_bytes(up + down)}"

    def _finish_monitor(self):
        """Takes a last reading, logs the session totals, forgets the monitor."""
        if self._health:
            self._health.stop()
            self._health = None
        if self._voice_probe:
            self._voice_probe.stop()
            self._voice_probe = None
            self._voiceq = None
        if self._voice_wd:
            self._voice_wd.stop()
            self._voice_wd = None
            self._voice_last = ("idle", 0.0, 0.0, self._voice_status.resets)
            self._refresh_voice_label()
        self._refresh_voiceq()
        if self._monitor:
            up, down = self._monitor.stop()
            self._monitor = None
            self._append_log(f"--- session total: ↑ {fmt_bytes(up)} uploaded, ↓ {fmt_bytes(down)} downloaded "
                             f"({fmt_bytes(up + down)} total) ---")

    def export_log(self):
        if not self._log_lines:
            messagebox.showinfo("Discord Proxy", "The log is empty.")
            return
        now = datetime.now()
        path = filedialog.asksaveasfilename(
            title="Export log",
            defaultextension=".txt",
            initialfile=f"discord-proxy-log-{now:%Y%m%d-%H%M%S}.txt",
            initialdir=config_dir() if os.path.isdir(config_dir()) else base_dir(),
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return
        header = [
            "Discord Proxy log",
            f"Exported: {now:%Y-%m-%d %H:%M:%S}",
            f"Proxy core: {self._active_core or self.core_var.get()}",
            f"Traffic: {self.lbl_traffic.cget('text')}",
            "(UUIDs, passwords, keys and pinned-cert hashes are masked automatically. The log may still "
            "contain your proxy server's address - remove it before sharing publicly.)",
            "-" * 60,
        ]
        try:
            with open(path, "w", encoding="utf-8", newline="\r\n") as f:
                f.write("\n".join(header + list(self._log_lines)) + "\n")
        except OSError as ex:
            messagebox.showerror("Discord Proxy", f"Could not save the log: {ex}")
            return
        self._append_log(f"--- log exported to {path} ---")

    # --------------------------------------------------------------- misc

    def open_config_folder(self):
        os.makedirs(config_dir(), exist_ok=True)
        try:
            os.startfile(config_dir())  # type: ignore[attr-defined]  (Windows only)
        except Exception as ex:
            messagebox.showerror("Discord Proxy", f"Could not open folder: {ex}")

    def open_discord(self):
        """Launches Discord from the default path (under the current Windows
        user's %LOCALAPPDATA%, then a file picker whose choice is remembered)."""
        candidates = [
            self._settings.get("discord_path") or "",
            DISCORD_DEFAULT_PATH,
        ]
        path = next((c for c in candidates if c and os.path.isfile(c)), None)
        if path is None:
            path = filedialog.askopenfilename(
                title="Locate Discord.exe",
                initialdir=os.path.dirname(DISCORD_DEFAULT_PATH),
                filetypes=[("Discord", "Discord.exe"), ("Programs", "*.exe")])
            if not path:
                return
            self._set_setting("discord_path", path)
        try:
            subprocess.Popen([path], cwd=os.path.dirname(path), close_fds=True)
        except Exception as ex:
            messagebox.showerror("Discord Proxy", f"Could not open Discord: {ex}")

    # ---------------------------------------------------- background -> GUI

    def _on_log_bg(self, line: str):
        self._event_queue.put(("log", line))

    def _on_exit_bg(self, code: int):
        self._event_queue.put(("exit", code))

    def _drain_event_queue(self):
        try:
            while True:
                kind, payload = self._event_queue.get_nowait()
                if kind == "log":
                    self._append_log(payload)
                elif kind == "exit":
                    self._on_singbox_exited(payload)
                elif kind == "stats":
                    self.lbl_traffic.configure(text=self._traffic_text(*payload))
                elif kind == "voicestat":
                    self._voice_last = payload
                    self._refresh_voice_label()
                    self._refresh_voiceq()
                elif kind == "voiceq":
                    self._on_voiceq(payload)
                elif kind == "testall":
                    self._on_testall(payload)
                elif kind == "update":
                    self._on_update_result(payload)
                elif kind == "dl":
                    self._on_dl_event(payload)
                elif kind == "verdict":
                    self._show_verdict(*payload)
                elif kind == "launch":
                    self._do_launch(payload)
                elif kind == "health":
                    self._on_health(*payload)
                elif kind == "rechain":
                    self._do_rechain(payload)
                elif kind == "voice":
                    self._on_voice_result(payload)
                elif kind == "voice_return":
                    self._on_voice_return(payload)
                elif kind == "discord_closed":
                    self._on_discord_closed(payload)
                elif kind == "cleanup":
                    self._cleanup_pending = False
                    for item in payload:
                        self._append_log(f"--- startup cleanup: removed {item} ---")
                    if payload:
                        self.status_bar.configure(text="Status: leftovers cleaned")
                elif kind == "tray":
                    if payload == "show":
                        self._restore_from_tray()
                    elif payload == "exit":
                        self._exit_completely()
                    elif payload == "start":
                        self.start_proxy()
                    elif payload == "stop":
                        self.stop_proxy()
        except queue.Empty:
            pass
        self.after(100, self._drain_event_queue)

    def _on_singbox_exited(self, code: int):
        self._finish_monitor()
        self._append_log(f"--- sing-box exited (code {code}) ---")

        if self._proc_token != self._launch_token:
            return  # a Stop / restart / shutdown we started ourselves is in charge

        if self._should_retry_launch(code):
            # Windows was still releasing the previous TUN adapter. Clean it
            # up and start again by itself (xray-core, if used, keeps running).
            self._retry += 1
            self._append_log(f"--- network adapter was busy; cleaning up and retrying "
                             f"automatically ({self._retry}/3) ---")
            self.status_bar.configure(text=f"Status: adapter busy - retry {self._retry}/3")
            self._set_proxy_state("retrying")
            self._notify("Network adapter busy",
                         f"Retrying ({self._retry}/3).",
                         "warning")
            self._begin_launch(extra_delay=2.0 * self._retry)
            return

        if not self._want_running or self._exiting:
            self._stop_everything()
            self.status_bar.configure(text="Status: stopped")
            return

        self._ks_engage("sing-box stopped")
        if time.monotonic() - self._launch_time < 20:
            # It never got going: explain why instead of restarting in a loop.
            self._want_running = False
            if self._auto_started:
                self._auto_suppressed = True
            self._stop_everything()
            self._report_failure()
            return

        # It ran for a while and then died: bring it back (with a limit).
        info = explain_failure(self._recent_lines())
        self._auto_recover(info[1] if info else "sing-box stopped unexpectedly")

    def _append_log(self, line: str):
        line = mask_secrets(strip_ansi(line))  # UUIDs / passwords / keys / pcs never reach the log
        self._log_lines.append(line)  # kept in memory only; shown via Export Log
        self._log_total += 1
        self._log_view_add(line)
        if "voice watchdog:" in line and "flow reset" in line:
            self._history.add_event("reset")
        elif line.startswith("--- auto-recover:") and "restarting" in line:
            self._history.add_event("restart")
        cidr = learn_range_from_log_line(line)
        if cidr:
            self._learn_range(cidr)
            # Voice fallback is only a short learning pass: as soon as Discord's UDP voice
            # media shows up (its range is now saved), go back to Discord-only capture
            # instead of keeping TeamSpeak/Steam/games inside the tunnel for the whole call.
            # (no early return: restarting the TUN adapter under a live call drops it and makes
            #  Windows flash "connection problem" again - we go back only after the call ends)
        self._voice_watch(line)

    def _learn_range(self, cidr: str):
        """Remembers a destination range Discord used (for 'Discord only' mode)."""
        if cidr in self._learned or len(self._learned) >= LEARNED_MAX:
            return
        self._learned.add(cidr)
        try:
            os.makedirs(config_dir(), exist_ok=True)
            with open(learned_ranges_path(), "w", encoding="utf-8") as f:
                f.write("# Learned automatically from Discord's connections - safe to delete.\n")
                f.write("\n".join(sorted(self._learned)) + "\n")
        except OSError:
            pass
        self._log_lines.append(f"--- learned Discord range {cidr} (used by \"Discord destinations only\" mode) ---")
        self._log_total += 1

    def _schedule_early_return(self, cidr: str):
        if self._early_return_pending or cidr in self._early_returned:
            return
        if not self._want_running or self._exiting:
            return
        self._early_return_pending = True
        gen = self._voice_return_gen
        self.after(4000, lambda: self._early_return(gen, cidr))   # let a few more ranges be learned

    def _early_return(self, gen: int, cidr: str):
        if (gen != self._voice_return_gen or not self._force_all or not self._want_running
                or self._exiting):
            self._early_return_pending = False
            return
        if self._recovering:                                      # still restarting - look again shortly
            self.after(2000, lambda: self._early_return(gen, cidr))
            return
        self._early_return_pending = False
        self._early_returned.add(cidr)
        self._voice_return(early=True)

    def _log_note(self, text: str):
        self._log_lines.append(text)
        self._log_total += 1

    # -------- voice watchdog ("Only Discord's destinations" mode) --------
    #
    # In that mode only the learned /22 ranges + fake-IP + DNS enter the
    # tunnel. Discord's voice UDP goes to a literal IP chosen per call; if it
    # is outside the learned ranges it leaves DIRECT (blocked/throttled): the
    # call connects through the tunnelled websocket, then the ping climbs to
    # several seconds and the connection drops. Here we notice that: after
    # Discord joins a *.discord.media voice server, UDP media must show up in
    # the tunnel within VOICE_CHECK_WINDOW_S. If it doesn't, this run switches
    # to capturing everything (which also learns the new range for next time).

    def _voice_watch(self, line: str):
        if (self._capture_active != "discord" or self._force_all or not self._want_running
                or self._recovering or self._exiting or self._voice_deadline is not None
                or not self._api):
            return
        if _VOICE_WS_RE.search(line):
            self._voice_deadline = time.monotonic() + VOICE_CHECK_WINDOW_S
            self._log_note(f"--- voice check: Discord joined a voice server; verifying in "
                           f"{VOICE_CHECK_WINDOW_S}s that its UDP media goes through the tunnel ---")
            self.after(int(VOICE_CHECK_WINDOW_S * 1000), lambda t=self._proc_token: self._voice_check(t))

    def _voice_check(self, token: int):
        api = self._api
        if (token != self._proc_token or not self._want_running or self._recovering
                or self._exiting or not api):
            self._voice_deadline = None
            return

        def worker():
            result = udp_voice_flowing(api["port"], api["secret"])
            self._event_queue.put(("voice", (token, result)))

        threading.Thread(target=worker, daemon=True).start()

    def _on_voice_result(self, payload):
        token, result = payload
        self._voice_deadline = None
        if (token != self._proc_token or not self._want_running or self._recovering
                or self._exiting or self._force_all):
            return
        if result is None:
            self._log_note("--- voice check: could not read sing-box's stats; leaving the capture as it is ---")
        elif result:
            self._log_note("--- voice check: OK - Discord's UDP voice media is going through the tunnel ---")
        else:
            self._voice_fallback()

    def _voice_fallback(self):
        self._force_all = True
        self._log_note("--- voice check: NO UDP voice media in the tunnel - this voice server is outside the "
                       "learned ranges (it would go direct: ping spike, then 'connection lost'). Capturing "
                       "everything for the rest of this run; the new range is learned for next time ---")
        self.status_bar.configure(
            text="Status: voice server not captured - reconnecting")
        self._set_proxy_state("retrying")
        self._announce_restored = False      # no "Proxy restored" pop-up for this planned restart
        self._restart_chain(delay=1.0)
        # Full capture is only a temporary measure for this call: go back to
        # "Discord destinations only" on its own once the call is over, so games
        # and everything else are not left running through the tunnel.
        self._voice_return_gen += 1
        self._voice_return_state = {"seen": False, "idle": 0, "start": time.monotonic()}
        gen = self._voice_return_gen
        self.after(20000, lambda: self._voice_return_tick(gen))

    def _voice_return_tick(self, gen: int):
        if (gen != self._voice_return_gen or not self._force_all or not self._want_running
                or self._exiting):
            return
        api = self._api
        if self._recovering or not api:          # still restarting - look again shortly
            self.after(5000, lambda: self._voice_return_tick(gen))
            return

        def worker():
            result = udp_voice_flowing(api["port"], api["secret"])
            self._event_queue.put(("voice_return", (gen, result)))

        threading.Thread(target=worker, daemon=True).start()

    def _on_voice_return(self, payload):
        gen, result = payload
        if (gen != self._voice_return_gen or not self._force_all or not self._want_running
                or self._exiting):
            return
        st = self._voice_return_state
        if result is True:
            st["seen"] = True
            st["idle"] = 0
        elif result is False:
            st["idle"] += 1
        waited = time.monotonic() - st.get("start", time.monotonic())
        # call is over = voice UDP was flowing and has now been gone for 3 checks (~30 s);
        # if it never came back after the restart, give up waiting after 3 minutes
        if st["idle"] >= 3 and (st["seen"] or waited > 180):
            if self._voice_call_active():      # mid-call guard: never restart under a running call
                st["idle"] = 0
            else:
                self._voice_return()
                return
        self.after(10000, lambda: self._voice_return_tick(gen))

    def _voice_return(self, early: bool = False):
        self._force_all = False
        self._early_return_pending = False
        self._voice_return_gen += 1
        if early:
            self._log_note("--- new Discord voice range learned: returning to 'Discord destinations only' "
                           "right away (TeamSpeak, Steam and games stay outside the tunnel) ---")
            self.status_bar.configure(text="Status: voice range learned - restarting")
        else:
            self._log_note("--- voice call finished and the new voice range is learned: returning to "
                           "'Discord destinations only' ---")
            self.status_bar.configure(text="Status: call ended - restarting")
        self._set_proxy_state("retrying")
        self._announce_restored = False
        self._restart_chain(delay=1.0)

    def _capture_settings(self) -> dict:
        """What the TUN should capture + whether strict_route is on, from Settings."""
        mode = self._settings.get("capture_mode", "discord")
        configured_mode = mode
        pref = self._settings.get("strict_route", "auto")
        capture: dict = {}
        if mode == "discord" and self._force_all:
            self._append_log("--- capture mode: voice fallback - capturing everything for the rest of this run ---")
            mode = "all"
        if mode == "discord":
            routes, reason = compute_discord_capture(self._learned)
            if routes is None:
                self._append_log(f"--- capture mode: {reason}; capturing everything this run "
                                 f"(Discord's ranges are learned from it) ---")
                if "ranges" in reason and not self._learning_note_shown:
                    self._learning_note_shown = True
                    self._notify("Learning run",
                                 "Join a voice channel once.")
                mode = "all"
            else:
                capture.update(routes)
        self._capture_active = mode
        # Learning pass = "Discord only" is configured but this run had to capture everything
        # (ranges unknown / voice fallback). The kill switch arms only once that pass is over.
        self._learning_run = (configured_mode == "discord" and mode == "all")
        strict = (mode == "all") if pref == "auto" else (pref == "on")
        capture["strict_route"] = strict
        capture["stack"] = self._settings.get("tun_stack", "mixed")
        capture["mtu"] = int(self._settings.get("tun_mtu", "1500"))
        if mode == "discord":
            self._append_log(f"--- capture mode: Discord destinations only ({len(capture['route_address'])} routes), "
                             f"strict_route {'on' if strict else 'off'} ---")
        else:
            self._append_log(f"--- capture mode: everything, strict_route {'on' if strict else 'off'} ---")
        return capture

    # ------------------------------------------------ close / tray / exit

    def _on_close(self):
        """The window's X button never exits by itself: it follows the saved
        choice, or asks (with a 'remember my choice' box)."""
        if self._exiting:
            return
        pref = self._settings.get("close_action", "tray")
        if pref in ("tray", "exit"):
            choice = pref
        else:
            choice, remember = self._ask_close_action()
            if choice and remember:
                self._settings["close_action"] = choice
                save_settings(self._settings)
        if choice == "tray":
            self._hide_to_tray()
        elif choice == "exit":
            self._exit_completely()
        # None -> dialog dismissed / Cancel: do nothing, keep running

    def _ask_close_action(self):
        dlg = tk.Toplevel(self)
        dlg.title("Discord Proxy")
        dlg.resizable(False, False)
        dlg.transient(self)
        self._style_toplevel(dlg)
        result = {"value": None}
        remember = tk.BooleanVar(value=False)

        def choose(v):
            result["value"] = v
            dlg.destroy()

        frame = ttk.Frame(dlg, padding=18)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="What would you like to do?", font=("Segoe UI", 11, "bold")).pack(anchor="w")
        ttk.Checkbutton(frame, text="Remember my choice",
                        variable=remember).pack(anchor="w", pady=(0, 12))
        row = ttk.Frame(frame)
        row.pack(fill="x")
        b1 = ttk.Button(row, text="Minimize to tray", command=lambda: choose("tray"))
        b1.pack(side="left")
        ttk.Button(row, text="Exit completely", command=lambda: choose("exit")).pack(side="left", padx=(8, 0))
        ttk.Button(row, text="Cancel", command=lambda: choose(None)).pack(side="right")
        dlg.protocol("WM_DELETE_WINDOW", lambda: choose(None))
        dlg.bind("<Escape>", lambda e: choose(None))

        dlg.update_idletasks()
        x = self.winfo_rootx() + (self.winfo_width() - dlg.winfo_width()) // 2
        y = self.winfo_rooty() + (self.winfo_height() - dlg.winfo_height()) // 3
        dlg.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        b1.focus_set()
        dlg.grab_set()
        self.wait_window(dlg)
        return result["value"], remember.get()

    def _hide_to_tray(self):
        self._remember_link()
        self._save_window_state()
        if self._tray and not self._tray.active:
            self._tray.start()
            self._set_proxy_state(self._state)
        if self._tray and self._tray.active:
            self.withdraw()
            if not self._hint_shown:
                self._hint_shown = True
                self._notify("Discord Proxy is still running",
                             "Click the tray icon to reopen.")
        else:
            # Never lose the window if the tray icon could not be created.
            self.iconify()
            messagebox.showwarning("Discord Proxy",
                                   "Tray icon failed - minimized to taskbar.")

    def _restore_from_tray(self):
        self.deiconify()
        self.state("normal")
        self._fit_window()                     # always come back at the default size, never a collapsed one
        self.lift()
        self.focus_force()
        # Windows can finish the un-hide after we return and hand back a squashed window
        # (only the top bar visible) - re-apply the default size once it has settled.
        self.after(60, self._fit_window)
        self.after(300, self._fit_window)

    def _exit_completely(self):
        """Stops everything (sing-box, xray, TUN adapter, tray) and ends the process."""
        if self._exiting:
            return
        self._exiting = True
        self._want_running = False
        self._ks_release_now()
        self._testall_cancel.set()
        self._dl_cancel.set()
        kill_test_processes()
        self._remember_link()
        self._save_window_state()
        try:
            self.deiconify()
            self.status_bar.configure(text="Status: shutting down...")
            self.update_idletasks()
        except Exception:
            pass
        # Never destroy the GUI before sing-box/TUN/xray cleanup has completed.
        if self._health:
            self._health.stop()
            self._health = None
        if self._tray:
            self._tray.stop()
            self._tray = None
        if self._monitor:
            self._monitor.stop()
            self._monitor = None
        xray, self._xray = self._xray, None

        def cleanup():
            try:
                self._manager.stop()          # also removes the TUN adapter when this run created one
                if xray:
                    xray.stop()
                if _TUN_STATE["used"]:
                    flush_dns()
            except Exception:
                pass

        worker = threading.Thread(target=cleanup, daemon=True)
        worker.start()
        deadline = time.monotonic() + 20.0     # never hang on exit, whatever Windows is doing
        while worker.is_alive() and time.monotonic() < deadline:
            try:
                self.update()
            except tk.TclError:
                break
            time.sleep(0.03)
        if self._single:
            self._single.release()
        try:
            self.destroy()
        except tk.TclError:
            pass

    # ------------------------------------------------------ theme / settings

    def _collect_muted(self, widget):
        for child in widget.winfo_children():
            if isinstance(child, ttk.Label):
                try:
                    if str(child.cget("foreground")) in ("#444444", "#777777"):
                        self._muted_labels.append(child)
                except tk.TclError:
                    pass
            self._collect_muted(child)

    def _titlebar_dark(self, win, dark=None):
        if os.name != "nt":
            return
        if dark is None:
            dark = self._is_dark
        try:
            from ctypes import wintypes
            win.update_idletasks()
            user32 = ctypes.WinDLL("user32")
            dwm = ctypes.WinDLL("dwmapi")
            user32.GetParent.argtypes = [wintypes.HWND]
            user32.GetParent.restype = wintypes.HWND
            dwm.DwmSetWindowAttribute.argtypes = [wintypes.HWND, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD]
            wid = win.winfo_id()
            hwnd = user32.GetParent(wid) or wid
            val = ctypes.c_int(1 if dark else 0)
            for attr in (20, 19):  # DWMWA_USE_IMMERSIVE_DARK_MODE (19 on early Windows 10 builds)
                if dwm.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(val), 4) == 0:
                    break
        except Exception:
            pass

    def _style_toplevel(self, win):
        win.configure(bg=self._pal["bg"])
        self._titlebar_dark(win)

    def _apply_theme(self):
        mode = self._settings.get("theme", "auto")
        dark = windows_prefers_dark() if mode == "auto" else mode == "dark"
        self._is_dark = dark
        st = ttk.Style(self)
        if not self._default_ttk_theme:
            self._default_ttk_theme = st.theme_use()
        if dark:
            pal = dict(DARK_PALETTE)
            bg, fg, field = pal["bg"], pal["fg"], pal["field"]
            btn, hover, border, muted = pal["btn"], pal["btn_hover"], pal["border"], pal["muted"]
            st.theme_use("clam")
            st.configure(".", background=bg, foreground=fg, fieldbackground=field, bordercolor=border,
                         troughcolor=bg, lightcolor=bg, darkcolor=bg, focuscolor=bg, insertcolor=fg)
            st.configure("TFrame", background=bg)
            st.configure("TLabel", background=bg, foreground=fg)
            st.configure("TLabelframe", background=bg, bordercolor=border)
            st.configure("TLabelframe.Label", background=bg, foreground=fg)
            st.configure("TButton", background=btn, foreground=fg, bordercolor=border, padding=(10, 4))
            st.map("TButton", background=[("disabled", bg), ("pressed", hover), ("active", hover)],
                   foreground=[("disabled", muted)])
            st.configure("TCombobox", fieldbackground=field, background=btn, foreground=fg,
                         arrowcolor=fg, bordercolor=border)
            st.map("TCombobox", fieldbackground=[("readonly", field)], foreground=[("readonly", fg)],
                   selectbackground=[("readonly", field)], selectforeground=[("readonly", fg)])
            for name in ("TCheckbutton", "TRadiobutton"):
                st.configure(name, background=bg, foreground=fg)
                st.map(name, background=[("active", bg)], foreground=[("disabled", muted)])
            st.configure("Treeview", background=field, fieldbackground=field, foreground=pal["field_fg"],
                         bordercolor=border)
            st.map("Treeview", background=[("selected", pal["sel"])], foreground=[("selected", pal["field_fg"])])
            st.configure("Treeview.Heading", background=btn, foreground=fg, bordercolor=border)
            st.configure("TNotebook", background=bg, bordercolor=border)
            st.configure("TNotebook.Tab", background=btn, foreground=fg, padding=(12, 4))
            st.map("TNotebook.Tab", background=[("selected", bg), ("active", hover)])
            st.configure("TSpinbox", fieldbackground=field, foreground=fg, arrowcolor=fg, bordercolor=border)
            st.configure("TEntry", fieldbackground=field, foreground=fg, insertcolor=fg, bordercolor=border)
            st.configure("TScrollbar", background=btn, troughcolor=bg, arrowcolor=fg, bordercolor=border)
            st.configure("Horizontal.TProgressbar", background=pal["ok"], troughcolor=field, bordercolor=border)
        else:
            pal = dict(LIGHT_PALETTE, bg=self._default_bg)
            st.theme_use(self._default_ttk_theme)
        self._pal = pal
        self.option_add("*TCombobox*Listbox.background", pal["field"])
        self.option_add("*TCombobox*Listbox.foreground", pal["field_fg"])
        self.option_add("*TCombobox*Listbox.selectBackground", pal["sel"])
        self.option_add("*TCombobox*Listbox.selectForeground", pal["field_fg"])
        self.configure(bg=pal["bg"])
        self.input_box.configure(bg=pal["field"], fg=pal["field_fg"], insertbackground=pal["field_fg"],
                                 selectbackground=pal["sel"], selectforeground=pal["field_fg"])
        self.log_text.configure(bg=pal["field"], fg=pal["field_fg"], insertbackground=pal["field_fg"],
                                selectbackground=pal["sel"], selectforeground=pal["field_fg"])
        self.hist_canvas.configure(bg=pal["field"], highlightbackground=pal.get("border", "#bdbdbd"),
                                   highlightcolor=pal.get("border", "#bdbdbd"))
        for menu in list(self._themed_menus):
            try:
                menu.configure(bg=pal["field"], fg=pal["field_fg"], activebackground=pal["sel"],
                               activeforeground=pal["field_fg"])
            except tk.TclError:
                self._themed_menus.remove(menu)  # destroyed widget
        alive = []
        for label in self._muted_labels:
            try:
                if label.winfo_exists():
                    label.configure(foreground=pal["muted"])
                    alive.append(label)
            except tk.TclError:
                pass  # label belonged to a Settings window that has been closed
        self._muted_labels[:] = alive
        for win in (self._settings_win, self._links_win, self._dl_win):
            if win is not None and win.winfo_exists():
                self._style_toplevel(win)
        self._redraw_history()
        self._render_update_labels()
        self._refresh_voiceq()
        self._titlebar_dark(self, dark)
        if self._theme_ready:
            self.refresh_all_status()

    def _capture_changed(self):
        if self._want_running:
            self.status_bar.configure(
                text="Status: applies on next Start")

    def _open_ranges_file(self):
        try:
            os.startfile(ensure_manual_ranges_file())  # type: ignore[attr-defined]  (Windows only)
        except Exception as ex:
            messagebox.showerror("Discord Proxy", f"Could not open the ranges file: {ex}")

    def _set_setting(self, key: str, value):
        self._settings[key] = value
        save_settings(self._settings)

    # ---- remembering things between runs

    def _remember_link(self, _event=None):
        """Saves the proxy link as soon as it is edited (not only when Start is
        pressed), so the next launch comes back exactly as it was left."""
        try:
            text = self._link_text().strip()
        except tk.TclError:
            return
        if text and self._settings.get("link") != text:
            self._settings["link"] = text
            save_settings(self._settings)

    def _restore_geometry(self):
        m = _GEOMETRY_RE.fullmatch(str(self._settings.get("geometry") or ""))
        if not m:
            return
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        if m.group(3) is None:
            return
        w = TOTAL_WIDTH                                        # size is fixed; only the position is restored
        x = max(-w + 100, min(int(m.group(3)), sw - 100))   # never restore fully off-screen
        y = max(0, min(int(m.group(4)), sh - 100))
        self.geometry(f"+{x}+{y}")

    def _on_configure(self, event):
        if event.widget is not self:
            return
        if self._geo_job is not None:
            try:
                self.after_cancel(self._geo_job)
            except tk.TclError:
                pass
        self._geo_job = self.after(800, self._save_window_state)

    def _save_window_state(self):
        self._geo_job = None
        try:
            if self.state() != "normal":
                return
            geo = self.geometry()
            if self.winfo_height() < 200:      # collapsed/transitional state - don't save it
                return
        except tk.TclError:
            return
        if self._settings.get("geometry") != geo:
            self._settings["geometry"] = geo
            save_settings(self._settings)

    def _reset_all(self, dlg, close_dlg):
        """Settings > Reset: back to a first-run state (asks first)."""
        if not messagebox.askyesno(
                "Discord Proxy - Reset all settings",
                "Stop the proxy and reset everything?", icon="warning", default="no", parent=dlg):
            return
        self._want_running = False
        self._recovering = False
        self._auto_suppressed = True
        self._stop_everything()
        removed = reset_saved_data()
        self._settings.clear()
        self._learned.clear()
        self._learning_note_shown = False
        self._force_all = False
        self._learning_run = False
        self._ks_release(force=True)
        self._voice_deadline = None
        self._voice_return_gen += 1
        self._capture_active = "all"
        self.input_box.delete("1.0", "end")
        self.input_box.insert("1.0", PLACEHOLDER)
        self.core_var.set("Auto (recommended)")
        self._history = ConnectionHistory()
        self._link_results = {}
        try:
            autostart_disable()            # the sign-in task is part of "everything"
        except Exception:
            pass
        self._apply_theme()
        self._apply_log_panel_visibility()
        self._fit_window()
        self._log_note(f"--- reset: all settings cleared ({', '.join(removed) or 'nothing was saved'}) ---")
        self.status_bar.configure(text="Status: settings reset")
        close_dlg()
        messagebox.showinfo("Discord Proxy", "Settings reset.")

    # =====================================================================
    # Connection history graph
    # =====================================================================

    def _history_tick(self):
        if self._exiting:
            return
        self._redraw_history()
        self.after(60000, self._history_tick)      # keeps the time axis moving while nothing new arrives

    def _redraw_history(self):
        cv = getattr(self, "hist_canvas", None)
        if cv is None:
            return
        try:
            cv.delete("all")
            W, H = max(240, cv.winfo_width()), HIST_H
            L, R, T, B = 38, 8, 8, 16
            pw, ph = W - L - R, H - T - B
            pal = self._pal
            muted = pal.get("muted", "#777777")
            now = time.time()
            t0 = now - HISTORY_WINDOW_S
            pings, events = self._history.snapshot(now)
            vals = [ms for _t, ms in pings if ms is not None]
            top = 100
            if vals:
                top = max(100, int(math.ceil(max(vals) * 1.15 / 50.0) * 50))

            def X(t):
                return L + (t - t0) / HISTORY_WINDOW_S * pw

            def Y(ms):
                return T + ph - min(ms, top) / top * ph

            for frac, label in ((0.0, "0"), (0.5, str(top // 2)), (1.0, str(top))):
                y = T + ph - frac * ph
                cv.create_line(L, y, W - R, y, fill=pal.get("border", "#d0d0d0"))
                cv.create_text(L - 4, y, text=label, anchor="e", fill=muted, font=("Segoe UI", 7))
            for frac, label in ((0.0, "-60 min"), (0.5, "-30"), (1.0, "now")):
                anchor = "w" if frac == 0.0 else ("e" if frac == 1.0 else "center")
                cv.create_text(L + frac * pw, H - 2, text=label, anchor="s" if False else anchor,
                               fill=muted, font=("Segoe UI", 7))
            # one column per time bucket: green = fine, red = a lossy / failed stretch (full height when no answer)
            nb = max(20, pw // 4)
            bw = pw / nb
            bucket_s = HISTORY_WINDOW_S / nb
            ok_vals = [[] for _ in range(nb)]
            bad = [False] * nb
            for t, ms in pings:
                i = min(nb - 1, max(0, int((t - t0) / bucket_s)))
                if ms is None:
                    bad[i] = True
                else:
                    ok_vals[i].append(ms)
            for i in range(nb):
                if not ok_vals[i] and not bad[i]:
                    continue
                x0 = L + i * bw
                top_y = (T if not ok_vals[i] else Y(max(ok_vals[i]) if bad[i] else sum(ok_vals[i]) / len(ok_vals[i])))
                top_y = min(top_y, T + ph - 2)
                cv.create_rectangle(x0, top_y, x0 + max(1.0, bw - 1), T + ph, outline="",
                                    fill="#d9534f" if bad[i] else pal.get("ok", "#2e9b4f"))
            avg, mx, drops, total = self._history.stats(now)
            if avg is not None:
                self.lbl_hist.configure(text=f"avg {avg:.0f} ms \u00b7 max {mx} ms \u00b7 lossy {drops}")
            else:
                self.lbl_hist.configure(text="No voice call yet")
        except tk.TclError:
            pass

    # =====================================================================
    # Voice quality readout (ping / loss / jitter)
    # =====================================================================

    def _on_voiceq(self, summary: dict):
        self._voiceq = summary
        if self._voice_last[0] != "idle" and summary.get("samples", 0) >= VoiceQualityProbe.MIN_SAMPLES:
            if summary.get("ping") is not None:
                self._history.add_ping(summary["ping"])
                if (summary.get("loss") or 0) >= 10:
                    self._history.add_ping(None)            # a lossy stretch shows as a red mark
            elif summary.get("dead"):
                self._history.add_ping(None)
            self._redraw_history()
        self._refresh_voiceq()

    def _refresh_voiceq(self):
        pal = getattr(self, "_pal", {}) or {}
        muted = pal.get("muted", "#777777")
        colors = {"good": "#2e9b4f", "fair": "#e0a030", "bad": "#d9534f"}
        q = self._voiceq
        in_call = self._voice_last[0] != "idle"
        flow = getattr(self._voice_status, "flow", "") or ""
        color = muted
        if self._voice_probe is None:
            text = "quality: off" if not self._settings.get("voice_probe", True) else "quality: not running"
            second = " "
        elif not in_call or q is None:
            text, second = "quality: no active voice call", " "
        elif q.get("dead"):
            text = "quality: no UDP answer through the proxy"
            second, color = " ", colors["bad"]
        elif q["samples"] < VoiceQualityProbe.MIN_SAMPLES or q.get("ping") is None:
            text, second = "quality: measuring...", (f"voice server {flow}" if flow else " ")
        else:
            grade = quality_grade(q["ping"], q["loss"], q["jitter"])
            color = colors[grade]
            jit = q["jitter"] if q["jitter"] is not None else 0.0
            text = f"ping {q['ping']:.0f} ms   loss {q['loss']:.1f}%   jitter {jit:.1f} ms"
            second = f"voice server {flow}" if flow else " "
        try:
            self.lbl_voiceq.configure(text=text + "\n" + second, foreground=color)
        except tk.TclError:
            pass

    # =====================================================================
    # Live log panel
    # =====================================================================

    def _apply_log_panel_visibility(self):
        try:
            if self._settings.get("show_log_panel", False):
                self._log_outer.pack(fill="both", expand=True)
                self._log_refilter()
            else:
                self._log_outer.pack_forget()
            self._fit_window()
        except tk.TclError:
            pass

    def _log_panel_live(self) -> bool:
        return bool(self._settings.get("show_log_panel", False))

    def _log_passes(self, line: str) -> bool:
        if self._log_errors.get() and not _LOG_ERR_RE.search(line):
            return False
        if self._log_discord.get() and not _LOG_DISCORD_RE.search(line):
            return False
        query = self._log_query.get().strip().lower()
        return not query or query in line.lower()

    def _log_insert(self, line: str):
        tag = "err" if _LOG_ERR_RE.search(line) else ("warn" if "warn" in line.lower() else "")
        self.log_text.insert("end", line + "\n", tag)

    def _log_view_add(self, line: str):
        if not self._log_panel_live() or not self._log_passes(line):
            return
        try:
            at_end = self.log_text.yview()[1] >= 0.98
            self.log_text.configure(state="normal")
            self._log_insert(line)
            rows = int(self.log_text.index("end-1c").split(".")[0])
            if rows > 1500:
                self.log_text.delete("1.0", f"{rows - 1500}.0")
            self.log_text.configure(state="disabled")
            if at_end:
                self.log_text.see("end")
            self._log_shown += 1
            self._log_update_count()
        except tk.TclError:
            pass

    def _log_schedule_refilter(self):
        if self._log_refilter_job is not None:
            try:
                self.after_cancel(self._log_refilter_job)
            except Exception:
                pass
        self._log_refilter_job = self.after(250, self._log_refilter)

    def _log_refilter(self):
        self._log_refilter_job = None
        if not self._log_panel_live():
            return
        try:
            lines = list(self._log_lines)
            first_abs = self._log_total - len(lines)           # absolute index of lines[0]
            skip = max(0, self._log_clear_at - first_abs)
            picked = []
            for line in reversed(lines[skip:]):
                if self._log_passes(line):
                    picked.append(line)
                    if len(picked) >= 1500:
                        break
            picked.reverse()
            self.log_text.configure(state="normal")
            self.log_text.delete("1.0", "end")
            for line in picked:
                self._log_insert(line)
            self.log_text.configure(state="disabled")
            self.log_text.see("end")
            self._log_shown = len(picked)
            self._log_update_count()
        except tk.TclError:
            pass

    def _log_update_count(self):
        try:
            self.lbl_logcount.configure(text=f"{self._log_shown} line(s) shown")
        except tk.TclError:
            pass

    def _log_clear_view(self):
        self._log_clear_at = self._log_total
        self._log_refilter()

    def _log_copy(self):
        try:
            text = self.log_text.get("1.0", "end-1c")
            self.clipboard_clear()
            self.clipboard_append(text)
        except tk.TclError:
            pass

    # =====================================================================
    # Saved links, failover, "test all"
    # =====================================================================

    def _saved_links(self) -> list:
        return sanitize_links(self._settings.get("links"))

    def _save_links(self, links: list):
        self._settings["links"] = links
        save_settings(self._settings)
        self._links_refresh_tree()

    def _active_link_text(self) -> str:
        if self._want_running and (self._last_text or "").strip():
            return self._last_text.strip()
        return self._link_text().strip()

    def _switch_to_link(self, text: str):
        """Makes `text` the link in the box, the remembered link and the one restarts use."""
        self._last_text = text
        self.input_box.delete("1.0", "end")
        self.input_box.insert("1.0", text)
        self._settings["link"] = text
        save_settings(self._settings)

    def _use_link(self, text: str, parent=None):
        self.input_box.delete("1.0", "end")
        self.input_box.insert("1.0", text)
        self._remember_link()
        self._links_refresh_tree()
        if self._want_running and not self._recovering and text.strip() != (self._last_text or "").strip():
            if messagebox.askyesno("Discord Proxy", "Switch the running proxy to this link now?\n\n"
                                   "A Discord voice call drops for a few seconds.", parent=parent or self):
                self.retry_connection()
        else:
            self.status_bar.configure(text="Status: link selected")

    def _next_failover_link(self):
        links = self._saved_links()
        if len(links) < 2:
            return None
        cur = (self._last_text or "").strip()
        idx = next((i for i, l in enumerate(links) if l["link"] == cur), -1)
        now = time.monotonic()
        for step in range(1, len(links) + 1):
            cand = links[(idx + step) % len(links)]
            if cand["link"] == cur:
                continue
            failed = self._link_failed_at.get(cand["link"])
            if failed is not None and now - failed < FAILOVER_MEMORY_S:
                continue
            return cand
        return None

    def _try_failover(self, reason: str) -> bool:
        """Switches to the next saved link (never more often than the auto-recover limit allows).
        Returns True when a switch was started."""
        if (not self._settings.get("failover", True) or self._recovering or self._exiting
                or not self._want_running):
            return False
        cand = self._next_failover_link()
        if cand is None:
            return False
        now = time.monotonic()
        self._recover_times = [t for t in self._recover_times if now - t < RECOVER_WINDOW_S]
        if len(self._recover_times) >= RECOVER_MAX:
            return False
        self._recover_times.append(now)
        old = (self._last_text or "").strip()
        self._link_failed_at[old] = now
        old_name = next((l["name"] for l in self._saved_links() if l["link"] == old), "the current link")
        self._switch_to_link(cand["link"])
        self._history.add_event("failover")
        self._redraw_history()
        self._append_log(f"--- failover: {reason} - '{old_name}' is not answering, switching to '{cand['name']}' ---")
        self.status_bar.configure(text=f"Status: switching to link '{cand['name']}'")
        self._set_proxy_state("retrying")
        self._notify("Proxy link not answering", f"Switching to '{cand['name']}'.", "warning")
        self._announce_restored = True
        self._health_lost = False
        self._ping_ms = None
        self._links_refresh_tree()
        self._restart_chain(delay=1.0)
        return True

    # ---- the server list in the right-hand pane

    def _open_links_dialog(self):
        self._links_tree.focus_set()

    def _links_on_select(self):
        """Stopped: highlighting a server makes it the one Start will use. Running: needs double-click."""
        if self._want_running or self._testall_running:
            return
        i = self._links_selected_index()
        links = self._saved_links()
        if i is None or i >= len(links):
            return
        link = links[i]["link"]
        if link == self._link_text().strip():
            return
        self.input_box.delete("1.0", "end")
        self.input_box.insert("1.0", link)
        self._remember_link()
        self._links_refresh_tree()

    def _links_alive(self) -> bool:
        return self._links_tree is not None

    def _link_meta(self, link: str):
        """(type, host:port) for the list columns - parsed once per link."""
        meta = self._link_meta_cache.get(link)
        if meta is None:
            ob, err = parse_proxy_link(link)
            if err or not ob:
                meta = ("?", "invalid link")
            else:
                host = ob.get("server") or ""
                meta = (str(ob.get("type", "?")), f"{host}:{ob.get('server_port')}" if host else "")
            self._link_meta_cache[link] = meta
        return meta

    def _links_status_refresh(self):
        if not self._links_alive() or self._testall_running:
            return
        n = len(self._saved_links())
        self._links_status_var.set(f"{n} server(s)" if n else "No servers - copy a link and press 'Paste link(s)'")

    def _links_refresh_tree(self):
        if not self._links_alive():
            return
        tree = self._links_tree
        try:
            sel = tree.selection()
            tree.delete(*tree.get_children())
            cur = self._active_link_text()
            links = self._saved_links()
            ranked = sorted((l for l in links if isinstance(self._link_results.get(l["link"]), dict)
                             and self._link_results[l["link"]].get("ok")),
                            key=lambda l: self._link_results[l["link"]]["ms"])
            rank = {l["link"]: i + 1 for i, l in enumerate(ranked)}
            for i, item in enumerate(links):
                res = self._link_results.get(item["link"])
                lat = status = ""
                tags = ()
                if res == "testing":
                    status = "testing..."
                elif isinstance(res, dict):
                    lat = f"{res['ms']} ms" if res.get("ms") is not None else "-"
                    status = (res.get("note") or "OK") if res["ok"] else (res.get("note") or "failed")
                    tags = ("best",) if rank.get(item["link"]) == 1 else (() if res["ok"] else ("bad",))
                mark = "\u25b6 " if item["link"] == cur else ""
                proto, addr = self._link_meta(item["link"])
                tree.insert("", "end", iid=str(i), tags=tags,
                            values=(rank.get(item["link"], ""), mark + item["name"], proto, addr, lat, status))
            kids = tree.get_children()
            target = next((str(i) for i, l in enumerate(links) if l["link"] == cur), None)
            if self._want_running and sel and sel[0] in kids:
                target = sel[0]                         # running: leave the user's own highlight alone
            elif target is None and sel and sel[0] in kids:
                target = sel[0]
            elif target is None and not cur and kids:
                target = kids[0]                        # nothing remembered yet: never leave the list unselected
            if target is not None and target in kids:
                tree.selection_set(target)
                tree.see(target)
        except tk.TclError:
            pass

    def _links_selected_index(self):
        if not self._links_alive():
            return None
        sel = self._links_tree.selection()
        return int(sel[0]) if sel else None

    def _links_add_current(self):
        text = self._link_text().strip()
        if not text:
            messagebox.showinfo("Discord Proxy", "Paste a proxy link in the main window first.", parent=self)
            return
        _ob, err = parse_proxy_link(text)
        if err:
            messagebox.showerror("Discord Proxy - Invalid Configuration", err, parent=self)
            return
        links = self._saved_links()
        if any(l["link"] == text for l in links):
            messagebox.showinfo("Discord Proxy", "This link is already saved.", parent=self)
            return
        if len(links) >= MAX_SAVED_LINKS:
            messagebox.showwarning("Discord Proxy", f"At most {MAX_SAVED_LINKS} links can be saved.",
                                   parent=self)
            return
        name = simpledialog.askstring("Saved links", "Name for this link:", initialvalue=default_link_name(text),
                                      parent=self)
        if name is None:
            return
        links.append({"name": name.strip()[:60] or default_link_name(text), "link": text})
        self._save_links(links)
        self._links_status_refresh()

    def _links_paste(self):
        try:
            clip = self.clipboard_get()
        except tk.TclError:
            clip = ""
        found = extract_links(clip)
        if not found and clip.strip().startswith("{"):
            ob, err = parse_proxy_link(clip.strip())
            if not err:
                found = [clip.strip()]
        if not found:
            messagebox.showinfo("Discord Proxy", "No proxy links (vless://, vmess://, trojan://, ss://, ...) "
                                "or outbound JSON were found on the clipboard.", parent=self)
            return
        links = self._saved_links()
        have = {l["link"] for l in links}
        added = dup = bad = 0
        for link in found:
            if link in have:
                dup += 1
                continue
            _ob, err = parse_proxy_link(link)
            if err or len(links) >= MAX_SAVED_LINKS:
                bad += 1
                continue
            links.append({"name": default_link_name(link) if not link.startswith("{") else "JSON outbound",
                          "link": link})
            have.add(link)
            added += 1
        self._save_links(links)
        self._links_status_refresh()
        messagebox.showinfo("Discord Proxy", f"Added {added} link(s)."
                            + (f" {dup} already saved." if dup else "") + (f" {bad} could not be used." if bad else ""),
                            parent=self)

    def _links_rename(self):
        i = self._links_selected_index()
        links = self._saved_links()
        if i is None or i >= len(links):
            return
        name = simpledialog.askstring("Saved links", "New name:", initialvalue=links[i]["name"],
                                      parent=self)
        if name and name.strip():
            links[i]["name"] = name.strip()[:60]
            self._save_links(links)

    def _links_remove(self):
        i = self._links_selected_index()
        links = self._saved_links()
        if i is None or i >= len(links):
            return
        removed = links.pop(i)
        self._link_results.pop(removed["link"], None)
        self._save_links(links)
        self._links_status_refresh()

    def _links_move(self, delta: int):
        i = self._links_selected_index()
        links = self._saved_links()
        if i is None or not 0 <= i + delta < len(links):
            return
        links[i], links[i + delta] = links[i + delta], links[i]
        self._save_links(links)
        self._links_tree.selection_set(str(i + delta))

    def _links_use_selected(self):
        i = self._links_selected_index()
        links = self._saved_links()
        if i is None or i >= len(links):
            messagebox.showinfo("Discord Proxy", "Select a link first.", parent=self)
            return
        self._use_link(links[i]["link"], parent=self)

    def _links_sort_speed(self):
        links = self._saved_links()
        ok = [l for l in links if (self._link_results.get(l["link"]) or {}).get("ok")]
        if not ok:
            messagebox.showinfo("Discord Proxy", "Press 'Test all' first - there are no results to sort by.",
                                parent=self)
            return
        ok.sort(key=lambda l: self._link_results[l["link"]]["ms"])
        rest = [l for l in links if l not in ok]
        self._save_links(ok + rest)
        self._links_status_var.set("Sorted by speed")

    def _links_test_all(self, only_selected: bool = False):
        if self._testall_running:
            return
        links = self._saved_links()
        if only_selected:
            i = self._links_selected_index()
            if i is None or i >= len(links):
                messagebox.showinfo("Discord Proxy", "Select a server first.", parent=self)
                return
            links = [links[i]]
        if not links:
            messagebox.showinfo("Discord Proxy", "No saved links to test.", parent=self)
            return
        if not os.path.isfile(singbox_exe_path()):
            messagebox.showwarning("Discord Proxy", "sing-box.exe not found.", parent=self)
            return
        self._testall_running = True
        self._testall_cancel.clear()
        if only_selected:
            self._link_results.pop(links[0]["link"], None)
        else:
            self._link_results = {}
        self._btn_testall.state(["disabled"])
        self._links_status_var.set(f"Testing 0/{len(links)}...")
        self._links_refresh_tree()
        self._append_log(f"--- test all: measuring {len(links)} saved link(s), one after the other"
                         + (" (separate instances - the running proxy is not touched)" if self._manager.is_running
                            else "") + " ---")
        threading.Thread(target=self._testall_worker,
                         args=([l["link"] for l in links], self._selected_core(), self._manager.is_running),
                         daemon=True).start()

    def _testall_worker(self, texts: list, core: str, bypass: bool):
        for i, text in enumerate(texts):
            if self._exiting or self._testall_cancel.is_set():
                break
            self._event_queue.put(("testall", ("start", i, len(texts), text)))
            ok, ms, note = measure_link_latency(text, core, bypass, self._testall_cancel)
            self._event_queue.put(("testall", ("result", i, len(texts), text, ok, ms, note)))
        self._event_queue.put(("testall", ("done",)))

    def _on_testall(self, payload):
        kind = payload[0]
        names = {l["link"]: l["name"] for l in self._saved_links()}
        if kind == "start":
            _k, i, n, text = payload
            self._link_results[text] = "testing"
            if self._links_alive():
                self._links_status_var.set(f"Testing {i + 1}/{n}: {names.get(text, '?')}...")
        elif kind == "result":
            _k, i, n, text, ok, ms, note = payload
            self._link_results[text] = {"ok": ok, "ms": ms, "note": note}
            self._append_log(f"--- test all: {names.get(text, '?')}: "
                             + (f"{ms} ms" + (f" ({note})" if note else "") if ok else f"FAILED - {note}") + " ---")
        elif kind == "done":
            self._testall_running = False
            for k, v in list(self._link_results.items()):
                if v == "testing":
                    del self._link_results[k]
            good = sorted(((v["ms"], k) for k, v in self._link_results.items() if isinstance(v, dict) and v["ok"]))
            if self._links_alive():
                self._btn_testall.state(["!disabled"])
                self._links_status_var.set(
                    f"Fastest: {names.get(good[0][1], '?')} ({good[0][0]} ms)" if good else
                    "No server answered")
            self.status_bar.configure(text="Status: test all finished" if not self._want_running
                                      else f"Status: running via {self._active_core} - test all finished")
        self._links_refresh_tree()

    # =====================================================================
    # Update checker
    # =====================================================================

    def _update_tick(self):
        if self._exiting:
            return
        if self._settings.get("check_updates", True):
            self._start_update_check(manual=False)
        self.after(UPDATE_CHECK_INTERVAL_S * 1000, self._update_tick)

    def _start_update_check(self, manual: bool):
        def worker():
            try:
                res = check_core_updates()
            except Exception as ex:
                res = [{"name": "update check", "error": str(ex)[:100], "outdated": False}]
            self._event_queue.put(("update", (res, manual)))

        threading.Thread(target=worker, daemon=True).start()

    def _on_update_result(self, payload):
        results, manual = payload
        self._update_results = [r for r in results if r.get("outdated")]
        self._render_update_labels()
        notified = dict(self._settings.get("update_notified") or {})
        changed = False
        for r in self._update_results:
            msg = f"{r['name']} {_fmt_ver(r['installed'])} -> {_fmt_ver(r['latest'])}"
            if self._update_logged.get(r["name"]) != msg:
                self._update_logged[r["name"]] = msg
                self._append_log(f"--- update available: {msg}  ({r['url']}) ---")
            if notified.get(r["name"]) != _fmt_ver(r["latest"]):
                notified[r["name"]] = _fmt_ver(r["latest"])
                changed = True
                self._notify("Update available", f"{r['name']} {_fmt_ver(r['latest'])} is out "
                             f"(you have {_fmt_ver(r['installed'])}).", "info")
        if changed:
            self._settings["update_notified"] = notified
            save_settings(self._settings)
        if manual:
            lines = []
            for r in results:
                if r.get("error"):
                    lines.append(f"{r['name']}: could not check ({r['error']})")
                elif r.get("outdated"):
                    lines.append(f"{r['name']}: {_fmt_ver(r['installed'])} -> {_fmt_ver(r['latest'])} available\n"
                                 f"   {r['url']}")
                else:
                    lines.append(f"{r['name']}: {_fmt_ver(r['installed']) if r.get('installed') else '?'} - up to date")
            messagebox.showinfo("Discord Proxy - Updates", "\n".join(lines) or
                                "No sing-box.exe / xray.exe found next to this script to check.")

    def _render_update_labels(self):
        try:
            for w in self.update_box.winfo_children():
                w.destroy()
            if self._update_results:
                if not self.btn_update.winfo_ismapped():
                    self.btn_update.pack(side="left", padx=(8, 0), after=self.btn_elevate)
            elif self.btn_update.winfo_ismapped():
                self.btn_update.pack_forget()
            for r in self._update_results:
                text = f"\u25b2 {r['name']} {_fmt_ver(r['installed'])} \u2192 {_fmt_ver(r['latest'])} available"
                lbl = ttk.Label(self.update_box, text=text, wraplength=WIN_WIDTH - 70, cursor="hand2",
                                foreground=self._pal["warn"], font=("Segoe UI", 9, "underline"))
                lbl.pack(anchor="w", pady=(2, 0))
                lbl.bind("<Button-1>", lambda _e, u=r["url"]: webbrowser.open(u))
            self._fit_window()
        except tk.TclError:
            pass

    def _update_components(self):
        """Replaces outdated sing-box / xray with the latest official release (stops the proxy first)."""
        names = {"sing-box": "sing-box", "xray-core": "xray"}
        comps = [names[r["name"]] for r in self._update_results if r["name"] in names]
        if not comps:
            return
        lines = ", ".join(f"{r['name']} {_fmt_ver(r['installed'])} \u2192 {_fmt_ver(r['latest'])}"
                          for r in self._update_results)
        extra = "\n\nThe running proxy will be stopped first." if self._want_running else ""
        if not messagebox.askyesno("Discord Proxy - Update", f"Update {lines}?{extra}", parent=self):
            return
        was_running = self._want_running
        if was_running:
            self.stop_proxy()
        self._run_download(comps, native_arch(), (lambda: self.start_proxy()) if was_running else None)

    # =====================================================================
    # Downloading missing components
    # =====================================================================

    def _missing_components(self) -> list:
        missing = []
        if not os.path.isfile(singbox_exe_path()):
            missing.append("sing-box")
        if not os.path.isfile(wintun_dll_path()):
            missing.append("wintun")
        if not os.path.isfile(xray_exe_path()):
            missing.append("xray")
        return missing

    def _offer_download(self, preselect=None, then=None, on_decline=None):
        """Asks before downloading anything. `then` runs after a fully successful install."""
        missing = self._missing_components()
        if not missing:
            if then:
                then()
            return
        if self._dl_win is not None and self._dl_win.winfo_exists():
            return
        arch = native_arch()
        dlg = tk.Toplevel(self)
        dlg.title("Download missing files")
        dlg.resizable(False, False)
        dlg.transient(self)
        self._style_toplevel(dlg)
        f = ttk.Frame(dlg, padding=18)
        f.pack(fill="both", expand=True)
        ttk.Label(f, text="Download the missing programs?", font=("Segoe UI", 11, "bold")).pack(anchor="w")
        sysl = ttk.Label(f, text=f"Your Windows: {_ARCH_LABEL.get(arch, arch)} - the matching builds are chosen.",
                         font=("Segoe UI", 9))
        sysl.pack(anchor="w", pady=(2, 8))
        vars_ = {}
        for comp in missing:
            info = COMPONENTS[comp]
            var = tk.BooleanVar(value=(comp in preselect) if preselect else True)
            vars_[comp] = var
            ttk.Checkbutton(f, variable=var, text=f"{info['file']}  ({'required' if info['required'] else 'optional'})"
                            ).pack(anchor="w")
            src = ttk.Label(f, text=info["source"], font=("Segoe UI", 8), wraplength=430, justify="left")
            src.configure(foreground=self._pal["muted"])
            self._muted_labels.append(src)
            src.pack(anchor="w", padx=(24, 0), pady=(0, 6))
        foot = ttk.Label(f, font=("Segoe UI", 8), text="Official sources only; files are verified.")
        foot.configure(foreground=self._pal["muted"])
        self._muted_labels.append(foot)
        foot.pack(anchor="w", pady=(4, 12))
        result = {"go": False}
        row = ttk.Frame(f)
        row.pack(fill="x")
        ttk.Button(row, text="Download", command=lambda: (result.update(go=True), dlg.destroy())).pack(side="left")
        ttk.Button(row, text="Not now", command=dlg.destroy).pack(side="left", padx=(8, 0))
        dlg.protocol("WM_DELETE_WINDOW", dlg.destroy)
        dlg.bind("<Escape>", lambda e: dlg.destroy())
        dlg.update_idletasks()
        x = self.winfo_rootx() + (self.winfo_width() - dlg.winfo_width()) // 2
        y = self.winfo_rooty() + 60
        dlg.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        dlg.grab_set()
        self.wait_window(dlg)
        for lbl in (src, foot):
            if lbl in self._muted_labels:
                self._muted_labels.remove(lbl)
        chosen = [c for c in missing if vars_[c].get()] if result["go"] else []
        if not chosen:
            if on_decline:
                on_decline()
            return
        self._run_download(chosen, arch, then)

    def _run_download(self, chosen: list, arch: str, then):
        self._dl_then = then
        self._dl_cancel = threading.Event()
        win = tk.Toplevel(self)
        self._dl_win = win
        win.title("Downloading")
        win.resizable(False, False)
        win.transient(self)
        self._style_toplevel(win)
        f = ttk.Frame(win, padding=18)
        f.pack(fill="both", expand=True)
        self._dl_label = ttk.Label(f, text="Starting...", width=58)
        self._dl_label.pack(anchor="w")
        self._dl_bar = ttk.Progressbar(f, length=420, maximum=100, mode="determinate")
        self._dl_bar.pack(pady=(8, 10))
        ttk.Button(f, text="Cancel", command=self._dl_cancel.set).pack(anchor="e")
        win.protocol("WM_DELETE_WINDOW", self._dl_cancel.set)
        win.update_idletasks()
        x = self.winfo_rootx() + (self.winfo_width() - win.winfo_width()) // 2
        y = self.winfo_rooty() + 80
        win.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        self._append_log(f"--- download: {', '.join(COMPONENTS[c]['file'] for c in chosen)} "
                         f"({_ARCH_LABEL.get(arch, arch)}) from the official sources ---")
        cancel = self._dl_cancel

        def worker():
            def progress(text, frac):
                self._event_queue.put(("dl", ("progress", text, frac)))

            results = install_components(chosen, arch, progress, cancel)
            self._event_queue.put(("dl", ("done", results)))

        threading.Thread(target=worker, daemon=True).start()

    def _on_dl_event(self, payload):
        kind = payload[0]
        if kind == "progress":
            _k, text, frac = payload
            try:
                self._dl_label.configure(text=text)
                if frac is not None:
                    self._dl_bar.configure(mode="determinate", value=max(0.0, min(1.0, frac)) * 100)
            except tk.TclError:
                pass
            return
        results = payload[1]
        try:
            if self._dl_win is not None:
                self._dl_win.destroy()
        except tk.TclError:
            pass
        self._dl_win = None
        for comp, ok, msg in results:
            self._append_log(f"--- download: {'OK' if ok else 'FAILED'} - {msg} ---")
        self.refresh_all_status()
        self._start_update_check(manual=False)
        all_ok = all(ok for _c, ok, _m in results)
        lines = [("\u2714 " if ok else "\u2718 ") + msg for _c, ok, msg in results]
        if all_ok:
            messagebox.showinfo("Discord Proxy", "\n\n".join(lines))
            then, self._dl_then = self._dl_then, None
            if then:
                self.after(200, then)
        else:
            messagebox.showwarning(
                "Discord Proxy - download problem",
                "\n\n".join(lines) + "\n\nYou can also download them by hand and put them next to this script:\n"
                "sing-box: github.com/SagerNet/sing-box/releases\nXray-core: github.com/XTLS/Xray-core/releases\n"
                "wintun.dll: www.wintun.net")

    # =====================================================================
    # Start with Windows / launch to tray
    # =====================================================================

    def _startup_hide(self):
        """Launched with --tray (the sign-in task): stay out of the way, only the tray icon shows."""
        if self._tray is not None and self._tray.active:
            return
        try:
            self.deiconify()
            self.iconify()           # no tray icon available: at least keep it on the taskbar
        except tk.TclError:
            pass

    def _autostart_refresh(self):
        """Keeps the sign-in task pointing at this script (it may have been moved)."""
        if self._exiting or not self._settings.get("autostart") or not is_admin():
            return
        delay = int(self._settings.get("autostart_delay_s", 30)) if self._settings.get("autostart_delay") else 0

        def worker():
            try:
                if autostart_exists():
                    autostart_enable(delay)
            except Exception:
                pass

        threading.Thread(target=worker, daemon=True).start()

    def _startup_download_prompt(self):
        if self._exiting or self._start_hidden or self._dl_prompted:
            return
        self._dl_prompted = True
        if [c for c in self._missing_components() if COMPONENTS[c]["required"]]:
            self._offer_download()

    # =====================================================================
    # Settings window
    # =====================================================================

    def _open_settings(self):
        if self._settings_win is not None and self._settings_win.winfo_exists():
            self._settings_win.lift()
            self._settings_win.focus_force()
            return
        dlg = tk.Toplevel(self)
        self._settings_win = dlg
        dlg.title("Settings")
        dlg.resizable(False, False)
        dlg.transient(self)
        self._style_toplevel(dlg)

        outer = ttk.Frame(dlg, padding=18)
        outer.pack(fill="both", expand=True)
        nb = ttk.Notebook(outer)
        nb.pack(fill="both", expand=True)
        tab_general = ttk.Frame(nb, padding=(10, 12, 10, 8))
        tab_network = ttk.Frame(nb, padding=(10, 12, 10, 8))
        tab_tools = ttk.Frame(nb, padding=(10, 12, 10, 8))
        nb.add(tab_general, text="General")
        nb.add(tab_network, text="Network")
        nb.add(tab_tools, text="Tools")
        settings_labels: list = []

        def heading(parent, text, first=False):
            ttk.Label(parent, text=text, font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0 if first else 14, 4))

        def note(parent, text):
            return                                  # explanations removed on purpose
            lbl = ttk.Label(parent, text=text, font=("Segoe UI", 8), wraplength=430, justify="left")
            lbl.configure(foreground=self._pal["muted"])
            self._muted_labels.append(lbl)
            settings_labels.append(lbl)
            lbl.pack(anchor="w", pady=(2, 0))

        # ------------------------------------------------------------ General
        t = tab_general
        heading(t, "Appearance", first=True)
        theme_var = tk.StringVar(value=self._settings.get("theme", "auto"))
        row = ttk.Frame(t)
        row.pack(anchor="w")
        for text, val in (("Match Windows", "auto"), ("Light", "light"), ("Dark", "dark")):
            ttk.Radiobutton(row, text=text, value=val, variable=theme_var,
                            command=lambda: (self._set_setting("theme", theme_var.get()), self._apply_theme())
                            ).pack(side="left", padx=(0, 14))

        heading(t, "Notifications")
        notif_var = tk.BooleanVar(value=bool(self._settings.get("notifications", True)))
        ttk.Checkbutton(t, text="Show Windows notifications", variable=notif_var,
                        command=lambda: self._set_setting("notifications", notif_var.get())).pack(anchor="w")

        heading(t, "Smart auto-start")
        auto_var = tk.BooleanVar(value=bool(self._settings.get("auto_mode", False)))

        def on_auto():
            self._set_setting("auto_mode", auto_var.get())
            self._auto_suppressed = False
            self._discord_gone_since = None

        ttk.Checkbutton(t, text="Start/stop with Discord", variable=auto_var, command=on_auto).pack(anchor="w")

        heading(t, "Start with Windows")
        as_var = tk.BooleanVar(value=autostart_exists())
        ad_var = tk.BooleanVar(value=bool(self._settings.get("autostart_delay", False)))
        try:
            sec0 = int(self._settings.get("autostart_delay_s", 30))
        except (TypeError, ValueError):
            sec0 = 30
        sec_var = tk.StringVar(value=str(max(5, min(600, sec0))))

        def delay_secs() -> int:
            if not ad_var.get():
                return 0
            try:
                return max(5, min(600, int(sec_var.get())))
            except ValueError:
                return 30

        cb_delay = ttk.Checkbutton(t, text="Wait before starting after I sign in", variable=ad_var)
        drow = ttk.Frame(t)
        spin = ttk.Spinbox(drow, from_=5, to=600, increment=5, width=5, textvariable=sec_var)
        ttk.Label(drow, text="seconds").pack(side="right", padx=(6, 0))

        def refresh_delay_state():
            on = as_var.get()
            cb_delay.state(["!disabled"] if on else ["disabled"])
            spin.state(["!disabled"] if (on and ad_var.get()) else ["disabled"])

        def reregister():
            if as_var.get():
                ok, msg = autostart_enable(delay_secs())
                if not ok:
                    messagebox.showerror("Discord Proxy", msg, parent=dlg)

        def on_autostart():
            if as_var.get():
                ok, msg = autostart_enable(delay_secs())
                if not ok:
                    as_var.set(False)
                    if not is_admin():
                        messagebox.showwarning(
                            "Discord Proxy", "Starting with Windows needs Administrator rights once (the sign-in task "
                            "runs elevated so there is no UAC prompt at login).\n\nUse 'Restart as Administrator' in the "
                            "main window, then tick this box again.", parent=dlg)
                    else:
                        messagebox.showerror("Discord Proxy", msg, parent=dlg)
            else:
                ok, msg = autostart_disable()
                if not ok:
                    as_var.set(True)
                    messagebox.showerror("Discord Proxy", msg, parent=dlg)
            self._set_setting("autostart", as_var.get())
            refresh_delay_state()

        def on_delay_toggle():
            self._set_setting("autostart_delay", ad_var.get())
            refresh_delay_state()
            reregister()

        def on_delay_change(_event=None):
            self._set_setting("autostart_delay_s", delay_secs() or 30)
            if ad_var.get():
                reregister()

        ttk.Checkbutton(t, text="Launch Discord Proxy in the tray when I sign in", variable=as_var,
                        command=on_autostart).pack(anchor="w")
        cb_delay.configure(command=on_delay_toggle)
        cb_delay.pack(anchor="w", padx=(22, 0))
        drow.pack(anchor="w", padx=(44, 0))
        spin.pack(side="left")
        spin.configure(command=on_delay_change)
        spin.bind("<Return>", on_delay_change)
        spin.bind("<FocusOut>", on_delay_change)
        refresh_delay_state()
        note(t, "Creates a Task Scheduler entry that runs at sign-in with the rights this tool needs. It only opens "
                "the tray icon - the proxy itself starts as usual (or with Discord, if smart auto-start is on).")

        heading(t, "When I close the window with the X button")
        close_var = tk.StringVar(value=self._settings.get("close_action", "tray"))
        for text, val in (("Ask me every time", "ask"), ("Minimize to tray (default)", "tray"),
                          ("Exit completely", "exit")):
            ttk.Radiobutton(t, text=text, value=val, variable=close_var,
                            command=lambda: self._set_setting("close_action", close_var.get())).pack(anchor="w")

        # ------------------------------------------------------------ Network
        t = tab_network
        heading(t, "Network capture (advanced)", first=True)
        cap_var = tk.StringVar(value=self._settings.get("capture_mode", "discord"))

        def on_capture():
            self._set_setting("capture_mode", cap_var.get())
            self._capture_changed()
            if cap_var.get() == "discord" and not self._learned:
                messagebox.showinfo("Discord Proxy",
                                    "Next run learns Discord's ranges - join a voice channel once.", parent=dlg)

        ttk.Radiobutton(t, text="Everything", value="all", variable=cap_var, command=on_capture).pack(anchor="w")
        ttk.Radiobutton(t, text="Only Discord's destinations (default)", value="discord", variable=cap_var,
                        command=on_capture).pack(anchor="w")
        srow = ttk.Frame(t)
        srow.pack(anchor="w", pady=(8, 0))
        ttk.Label(srow, text="Strict route:").pack(side="left", padx=(0, 8))
        strict_var = tk.StringVar(value=self._settings.get("strict_route", "auto"))
        for text, val in (("Auto", "auto"), ("On", "on"), ("Off", "off")):
            ttk.Radiobutton(srow, text=text, value=val, variable=strict_var,
                            command=lambda: (self._set_setting("strict_route", strict_var.get()),
                                             self._capture_changed())).pack(side="left", padx=(0, 10))
        ttk.Button(srow, text="Edit extra ranges...", command=self._open_ranges_file).pack(side="left", padx=(10, 0))

        trow = ttk.Frame(t)
        trow.pack(anchor="w", pady=(8, 0))
        ttk.Label(trow, text="TUN stack:").pack(side="left", padx=(0, 8))
        stack_var = tk.StringVar(value=self._settings.get("tun_stack", "mixed"))
        for text, val in (("Mixed (default)", "mixed"), ("System", "system"), ("gVisor", "gvisor")):
            ttk.Radiobutton(trow, text=text, value=val, variable=stack_var,
                            command=lambda: (self._set_setting("tun_stack", stack_var.get()),
                                             self._capture_changed())).pack(side="left", padx=(0, 10))
        mrow = ttk.Frame(t)
        mrow.pack(anchor="w", pady=(4, 0))
        ttk.Label(mrow, text="TUN MTU:").pack(side="left", padx=(0, 8))
        mtu_var = tk.StringVar(value=self._settings.get("tun_mtu", "1500"))
        for text, val in (("9000", "9000"), ("1500 (default)", "1500"), ("1400", "1400")):
            ttk.Radiobutton(mrow, text=text, value=val, variable=mtu_var,
                            command=lambda: (self._set_setting("tun_mtu", mtu_var.get()),
                                             self._capture_changed())).pack(side="left", padx=(0, 10))

        heading(t, "Kill switch")
        ks_var = tk.BooleanVar(value=bool(self._settings.get("kill_switch", True)))

        def on_ks():
            self._set_setting("kill_switch", ks_var.get())
            if not ks_var.get():
                self._ks_release("turned off in Settings", force=True)

        ttk.Checkbutton(t, text="Block Discord completely if the proxy fails", variable=ks_var,
                        command=on_ks).pack(anchor="w")
        ttk.Button(t, text="Unblock Discord now",
                   command=lambda: self._ks_release("unblocked by you", force=True)).pack(anchor="w", pady=(6, 0))
        note(t, "Active only after Discord's voice range is learned (or when 'Everything' is chosen) - never during "
                "the learning run. If the proxy dies or is being restarted, a Windows Firewall rule stops Discord from "
                "connecting directly; it is lifted as soon as the proxy answers again, when you press Stop, or on exit. "
                "Needs Administrator.")

        heading(t, "Servers (right-hand list)")
        fo_var = tk.BooleanVar(value=bool(self._settings.get("failover", True)))
        ttk.Checkbutton(t, text="Switch to the next saved link when the active one stops answering",
                        variable=fo_var, command=lambda: self._set_setting("failover", fo_var.get())).pack(anchor="w")
        note(t, "Failover needs at least two saved links. It switches after the proxy server has not answered "
                f"for about {FAILOVER_FAILS} health checks in a row.")

        heading(t, "Voice quality readout")
        vp_var = tk.BooleanVar(value=bool(self._settings.get("voice_probe", True)))

        def on_probe():
            self._set_setting("voice_probe", vp_var.get())
            if self._want_running:
                self.status_bar.configure(text="Status: applies on next Start")

        ttk.Checkbutton(t, text="Measure ping, packet loss and jitter during voice calls", variable=vp_var,
                        command=on_probe).pack(anchor="w")
        note(t, "While you are in a voice call, 4 tiny UDP test packets per second (about 35 bytes each) go through "
                "the same proxy as your call; the ones that get no answer are counted as loss. It measures the "
                "proxy's UDP path - sing-box does not expose Discord's own packet statistics.")

        # -------------------------------------------------------------- Tools
        t = tab_tools
        heading(t, "Live log", first=True)
        lp_var = tk.BooleanVar(value=bool(self._settings.get("show_log_panel", False)))
        ttk.Checkbutton(t, text="Show a live log panel in the main window", variable=lp_var,
                        command=lambda: (self._set_setting("show_log_panel", lp_var.get()),
                                         self._apply_log_panel_visibility())).pack(anchor="w")
        note(t, "A collapsible log with search plus 'Errors only' and 'Discord only' filters. Off by default - "
                "Export Log (.txt) always works.")

        heading(t, "Updates")
        up_var = tk.BooleanVar(value=bool(self._settings.get("check_updates", True)))
        ttk.Checkbutton(t, text="Warn me when sing-box or Xray-core is outdated", variable=up_var,
                        command=lambda: self._set_setting("check_updates", up_var.get())).pack(anchor="w")
        ttk.Button(t, text="Check now", command=lambda: self._start_update_check(manual=True)
                   ).pack(anchor="w", pady=(6, 0))
        note(t, "Reads the newest release number from github.com (SagerNet/sing-box, XTLS/Xray-core) about every "
                "12 hours. Nothing is downloaded or changed.")

        heading(t, "Missing programs")
        ttk.Button(t, text="Download missing files...", command=lambda: self._offer_download()).pack(anchor="w")
        note(t, f"sing-box.exe, wintun.dll and xray.exe from their official sources, for your Windows "
                f"({_ARCH_LABEL.get(native_arch(), native_arch())}). Always asks first.")

        def close_dlg():
            for lbl in settings_labels:
                try:
                    self._muted_labels.remove(lbl)
                except ValueError:
                    pass
            self._settings_win = None
            dlg.destroy()

        bottom = ttk.Frame(outer)
        bottom.pack(fill="x", pady=(14, 0))
        ttk.Button(bottom, text="Reset all settings...",
                   command=lambda: self._reset_all(dlg, close_dlg)).pack(side="left")
        ttk.Button(bottom, text="Close", command=close_dlg).pack(side="right")
        dlg.protocol("WM_DELETE_WINDOW", close_dlg)
        dlg.bind("<Escape>", lambda e: close_dlg())

        dlg.update_idletasks()
        x = self.winfo_rootx() + (self.winfo_width() - dlg.winfo_width()) // 2
        y = self.winfo_rooty() + 40
        dlg.geometry(f"+{max(x, 0)}+{max(y, 0)}")


def main():
    if os.name != "nt":
        print("This tool is Windows-only (it wraps sing-box's Windows TUN support).")
        sys.exit(1)
    single = SingleInstance()
    if not single.acquire():
        if not single.signalled:
            # Could not reach the running copy (e.g. it runs elevated, this one doesn't).
            ctypes.windll.user32.MessageBoxW(
                None, "Discord Proxy is already running - look for its icon in the system tray "
                      "(or the taskbar).", "Discord Proxy", 0x40)
        sys.exit(0)
    app = DiscordProxyApp(single, start_hidden="--tray" in sys.argv[1:])
    app.mainloop()
    # The window is gone and cleanup is done - make sure no helper thread or
    # child process keeps the program alive.
    os._exit(0)


if __name__ == "__main__":
    main()
