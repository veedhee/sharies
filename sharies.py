#!/usr/bin/env python3
"""
sharies - share one keyboard + mouse between two Linux machines.

  * The "share" side owns the physical keyboard/mouse. It grabs them
    exclusively and routes every event either to local virtual clones
    (uinput) or over the network. The hotkey (default Ctrl+Shift+/) flips the
    route and is never seen by either desktop.
  * The "receive" side recreates identical virtual devices with uinput and
    replays the events. Because this happens at the kernel level it works the
    same under Wayland, X11 and the text console.
  * Devices that are plugged in, or reconnect (Bluetooth, resume), while
    sharies is running are picked up within about a second.

Security:
  * TLS 1.3 only, mutual authentication, each side pins the other's exact
    self-signed certificate (no CAs, no passwords, no trust-on-first-use).
  * The receiver runs one session at a time, bounds every message, and
    injects only event codes the device declared when it was announced.
  * A 1 s heartbeat in both directions: if the link dies while you are
    controlling the remote machine, input returns to the local machine within
    ~3 s and the remote machine releases every held key.
  * If sharies exits or crashes, the kernel drops the grab and your devices
    work normally again.

Requires: python3-evdev (apt install python3-evdev), openssl (for genkey).
"""
import argparse
import asyncio
import hashlib
import hmac
import inspect
import json
import os
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
from pathlib import Path

PROTO_VERSION = 2
DEFAULT_PORT = 24850
REC = struct.Struct("!BHHi")            # wire record: device id, type, code, value
INPUT_EVENT = struct.Struct("llHHi")    # the kernel's struct input_event
SYN = INPUT_EVENT.pack(0, 0, 0, 0, 0)
CTRL, PING = 254, 255                   # reserved device ids
OP_HELLO, OP_ADD, OP_REMOVE = 0, 1, 2   # CTRL records: "type" is the operation
ACK_OK, ACK_BAD_VERSION, PONG = b"\x01", b"\x00", b"\x02"
MAX_DEVICES = 16
MAX_DESC = 64 * 1024                    # one device description (JSON)
MAX_FRAME = 1024                        # events between two SYN_REPORTs
MAX_BACKLOG = 1 << 20                   # unsent bytes before the link counts as dead
HEARTBEAT_EVERY = 1.0
HEARTBEAT_TIMEOUT = 3.0
RETRY_EVERY = 2.0
SCAN_EVERY = 1.0
NAME_PREFIX = "sharies"                 # cert CN, and the "phys" tag on our clones
DEFAULT_HOTKEY = "ctrl+shift+slash"
MODIFIERS = {
    "ctrl": ("KEY_LEFTCTRL", "KEY_RIGHTCTRL"),
    "shift": ("KEY_LEFTSHIFT", "KEY_RIGHTSHIFT"),
    "alt": ("KEY_LEFTALT", "KEY_RIGHTALT"),
    "super": ("KEY_LEFTMETA", "KEY_RIGHTMETA"),
}
DEFAULT_DIR = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "sharies"
PERMISSION_HINT = "Is your user in the 'input' group, and have you logged out and in since? (see README)"


def log(*a):
    print("[sharies]", *a, file=sys.stderr, flush=True)


def load_evdev():
    try:
        import evdev
    except ImportError:
        sys.exit("python3-evdev is required: sudo apt install python3-evdev")
    if "phys" not in inspect.signature(evdev.UInput.__init__).parameters:
        sys.exit("python3-evdev is too old (1.3 or newer is needed)")
    return evdev


# --------------------------------------------------------------------------- #
# Keys and TLS
# --------------------------------------------------------------------------- #
def fingerprint(der: bytes) -> str:
    h = hashlib.sha256(der).hexdigest().upper()
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


def read_cert_der(path) -> bytes:
    try:
        return ssl.PEM_cert_to_DER_cert(Path(path).read_text())
    except (OSError, ValueError) as exc:
        sys.exit(f"cannot read certificate {path}: {exc}")


def peer_cert_path(args) -> Path:
    return Path(args.peer_cert) if args.peer_cert else Path(args.dir) / "peer.pem"


# A complete, minimal OpenSSL config, so the certificate doesn't depend on the
# machine's /etc/ssl/openssl.cnf (which differs between versions and setups).
CERT_CONFIG = """\
[req]
distinguished_name = dn
prompt = no
x509_extensions = ext
[dn]
CN = {cn}
[ext]
basicConstraints = critical,CA:FALSE
"""


def openssl_verify(cert, trusted, purpose):
    """Ask this machine's OpenSSL whether `cert` is accepted when `trusted` is
    the only trusted certificate. Returns None if accepted (or if the openssl
    tool is missing), else OpenSSL's reason."""
    try:
        r = subprocess.run(["openssl", "verify", "-purpose", purpose, "-CAfile", str(trusted), str(cert)],
                           capture_output=True, text=True, timeout=10,
                           env=dict(os.environ, OPENSSL_CONF="/dev/null"))
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode == 0:
        return None
    lines = [ln for ln in (r.stdout + r.stderr).splitlines() if "error" in ln.lower()]
    return (lines[0].split(":", 3)[-1].strip() if lines else "rejected") or "rejected"


def cmd_genkey(args):
    d = Path(args.dir)
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    key, cert = d / "key.pem", d / "cert.pem"
    if key.exists() and not args.force:
        sys.exit(f"{key} already exists (use --force to replace it)")
    cn = NAME_PREFIX + "-" + "".join(ch for ch in socket.gethostname() if ch.isalnum() or ch in "-.")[:40]
    cnf = d / "openssl.cnf"
    old = os.umask(0o077)
    try:
        cnf.write_text(CERT_CONFIG.format(cn=cn))
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "ec",
             "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-sha256",
             "-keyout", str(key), "-out", str(cert), "-days", "3650", "-config", str(cnf)],
            check=True, capture_output=True, env=dict(os.environ, OPENSSL_CONF=str(cnf)))
    except FileNotFoundError:
        sys.exit("the openssl tool is missing: sudo apt install openssl")
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", b"") or b""
        sys.exit(f"openssl failed: {exc} {detail.decode(errors='replace').strip()}")
    finally:
        os.umask(old)
        cnf.unlink(missing_ok=True)
    os.chmod(key, 0o600)
    os.chmod(cert, 0o644)
    for purpose in ("sslclient", "sslserver"):
        why = openssl_verify(cert, cert, purpose)
        if why:
            key.unlink(missing_ok=True)
            cert.unlink(missing_ok=True)
            sys.exit(f"the new certificate failed its self-test ({why}). Please report this.")
    print(f"private key : {key} (keep secret)")
    print(f"certificate : {cert} (copy this to the other machine as {d / 'peer.pem'})")
    print(f"fingerprint : {fingerprint(read_cert_der(cert))}")


def cmd_fingerprint(args):
    own, peer = Path(args.dir) / "cert.pem", peer_cert_path(args)
    print(f"this machine : {fingerprint(read_cert_der(own))}")
    if peer.exists():
        print(f"peer         : {fingerprint(read_cert_der(peer))}")
    else:
        print(f"peer         : (no certificate at {peer} yet)")


def make_ctx(server_side: bool, d: Path, peer_cert: Path):
    """Return (TLS context, pinned peer certificate in DER form)."""
    key, cert = d / "key.pem", d / "cert.pem"
    if not key.exists() or not cert.exists():
        sys.exit(f"no key in {d}. Run 'sharies genkey' first.")
    if key.stat().st_mode & 0o077:
        sys.exit(f"{key} is readable by others; run: chmod 600 {key}")
    if not peer_cert.exists():
        sys.exit(f"{peer_cert} not found. Copy the other machine's cert.pem there (see README).")
    peer_der = read_cert_der(peer_cert)
    if peer_der == read_cert_der(cert):
        sys.exit(f"{peer_cert} is this machine's own certificate. Copy the OTHER machine's cert.pem.")
    # The peer checks us as a TLS client or server, and we check it as the other.
    why = openssl_verify(peer_cert, peer_cert, "sslclient" if server_side else "sslserver")
    if why:
        sys.exit(f"{peer_cert} cannot be used ({why}).\n"
                 "Fix: on the OTHER machine run 'sharies genkey --force' (with this version of sharies),\n"
                 "then copy its new cert.pem here as peer.pem, and copy this machine's cert.pem there again.")
    why = openssl_verify(cert, cert, "sslserver" if server_side else "sslclient")
    if why:
        sys.exit(f"{cert} cannot be used ({why}).\n"
                 "Fix: run 'sharies genkey --force' here, then copy the new cert.pem to the other machine as peer.pem.")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server_side else ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    if server_side:
        ctx.num_tickets = 0                 # no session resumption: full mutual auth every time
    else:
        ctx.check_hostname = False          # identity is the pinned cert, not a name
    ctx.verify_mode = ssl.CERT_REQUIRED
    try:
        ctx.load_cert_chain(cert, key)
        ctx.load_verify_locations(cafile=str(peer_cert))
    except (OSError, ssl.SSLError) as exc:
        sys.exit(f"TLS setup failed: {exc}")
    return ctx, peer_der


TLS_HINTS = {
    "self-signed certificate": "Its certificate is not the one in this machine's peer.pem "
                               "(compare 'sharies fingerprint' on both machines).",
    "unable to get local issuer certificate": "Its certificate is not the one in this machine's peer.pem "
                                              "(compare 'sharies fingerprint' on both machines).",
    "certificate is not yet valid": "This machine's clock is behind the other's: sudo timedatectl set-ntp true",
    "certificate has expired": "Run 'sharies genkey --force' on the other machine and copy its cert again.",
    "peer did not return a certificate": "The other side sent no certificate: is it running sharies share?",
}


def tls_reason(exc) -> str:
    """A short, human-readable reason for a TLS or connection failure."""
    if isinstance(exc, asyncio.IncompleteReadError):
        return "the other side closed the connection"
    for attr in ("verify_message", "reason", "strerror"):
        val = getattr(exc, attr, None)
        if val:
            return str(val).replace("_", " ").lower() if attr == "reason" else str(val)
    return str(exc) or type(exc).__name__


def peer_matches(writer, expected_der: bytes) -> bool:
    """The handshake already verified against the pinned cert; also require the
    presented certificate to be byte-identical to it."""
    sslobj = writer.get_extra_info("ssl_object")
    got = sslobj.getpeercert(binary_form=True) if sslobj else None
    return bool(got) and hmac.compare_digest(got, expected_der)


# --------------------------------------------------------------------------- #
# Devices (shared by both sides)
# --------------------------------------------------------------------------- #
def allowed_types(ecodes):
    # type -> highest valid code
    return {ecodes.EV_KEY: ecodes.KEY_MAX, ecodes.EV_REL: ecodes.REL_MAX,
            ecodes.EV_ABS: ecodes.ABS_MAX, ecodes.EV_MSC: ecodes.MSC_MAX}


def event_nodes():
    nodes = [p for p in Path("/dev/input").glob("event*") if p.name[5:].isdigit()]
    return [str(p) for p in sorted(nodes, key=lambda p: int(p.name[5:]))]


def describe(dev, ecodes, extra=None):
    types = {**allowed_types(ecodes), **(extra or {})}
    caps = {}
    for t, codes in dev.capabilities(absinfo=True).items():
        if t not in types:
            continue
        if t == ecodes.EV_ABS:
            caps[str(t)] = [[c, list(ai)] for c, ai in codes]
        else:
            caps[str(t)] = list(codes)
    i = dev.info
    props = list(dev.input_props()) if hasattr(dev, "input_props") else []
    return {"name": dev.name, "bustype": i.bustype, "vendor": i.vendor,
            "product": i.product, "version": i.version, "props": props, "caps": caps}


def is_clone(dev):
    return (dev.phys or "").startswith(NAME_PREFIX)


def is_shareable(dev, ecodes):
    if is_clone(dev):
        return False
    caps = dev.capabilities(absinfo=False)
    keys = set(caps.get(ecodes.EV_KEY, []))
    rel = set(caps.get(ecodes.EV_REL, []))
    absx = set(caps.get(ecodes.EV_ABS, []))
    keyboard = {ecodes.KEY_A, ecodes.KEY_SPACE} <= keys
    mouse = ecodes.REL_X in rel and ecodes.BTN_LEFT in keys
    touchpad = ecodes.ABS_X in absx and ecodes.BTN_TOUCH in keys and ecodes.BTN_TOOL_FINGER in keys
    return keyboard or mouse or touchpad


def clean_name(s):
    # Keep the original name so libinput applies the same device quirks.
    s = "".join(ch for ch in str(s) if ch.isprintable()).strip()[:72]
    return s or f"{NAME_PREFIX} device"


def u16(x):
    x = int(x)
    if not 0 <= x <= 0xFFFF:
        raise ValueError("out of range")
    return x


def build_uinput(evdev, desc, extra=None):
    """Validate a device description and create a uinput clone of it.
    Returns (uinput, set of allowed (type, code))."""
    e = evdev.ecodes
    types = {**allowed_types(e), **(extra or {})}
    caps, allowed = {}, set()
    for t_s, codes in dict(desc["caps"]).items():
        t = int(t_s)
        if t not in types or not isinstance(codes, list) or len(codes) > 1024:
            continue
        if t == e.EV_ABS:
            entries = []
            for c, ai in codes:
                c = int(c)
                vals = [int(x) for x in ai]
                if 0 <= c <= types[t] and len(vals) == 6:
                    entries.append((c, evdev.AbsInfo(*vals)))
                    allowed.add((t, c))
            if entries:
                caps[t] = entries
        else:
            cs = sorted({int(c) for c in codes if 0 <= int(c) <= types[t]})
            if cs:
                caps[t] = cs
                allowed.update((t, c) for c in cs)
    if not caps:
        raise ValueError("device declares no usable events")
    kw = dict(events=caps, name=clean_name(desc.get("name", "")),
              vendor=u16(desc.get("vendor", 1)), product=u16(desc.get("product", 1)),
              version=u16(desc.get("version", 1)), bustype=u16(desc.get("bustype", e.BUS_VIRTUAL)),
              phys=NAME_PREFIX)
    if "input_props" in inspect.signature(evdev.UInput.__init__).parameters:
        kw["input_props"] = [int(p) for p in desc.get("props", []) if 0 <= int(p) <= e.INPUT_PROP_MAX]
    ui = quiet_uinput(evdev)(**kw)
    return ui, allowed


_QUIET = {}


def quiet_uinput(evdev):
    """evdev.UInput, minus its attempt to open the new device for reading.
    Without the 'input' group (the receiver doesn't need it) that attempt
    blocks for 2 s per device, stalling the session, and then fails after the
    device was already created. We only ever write to the uinput fd."""
    base = evdev.UInput
    if base not in _QUIET:
        _QUIET[base] = type("QuietUInput", (base,), {"_find_device": lambda self, *a: None})
    return _QUIET[base]


def inject(ui, frame):
    """Write one frame of (type, code, value) events plus SYN_REPORT in one syscall."""
    pack = INPUT_EVENT.pack
    os.write(ui.fd, b"".join([pack(0, 0, t, c, v) for t, c, v in frame]) + SYN)


def cmd_list(args):
    evdev = load_evdev()
    found = denied = 0
    for p in event_nodes():
        try:
            d = evdev.InputDevice(p)
        except PermissionError:
            denied += 1
            continue
        except OSError:
            continue
        if is_shareable(d, evdev.ecodes):
            print(f"{p:22} {d.name}")
            found += 1
        d.close()
    if not found:
        sys.exit("no keyboard/mouse found. " + (PERMISSION_HINT if denied else ""))


# --------------------------------------------------------------------------- #
# Share side (has the physical keyboard/mouse, connects out)
# --------------------------------------------------------------------------- #
def parse_hotkey(spec, ecodes):
    """'ctrl+shift+slash' -> (list of modifier groups, trigger keycode)."""
    parts = [p.strip().lower() for p in spec.split("+") if p.strip()]
    if not parts:
        raise ValueError("empty hotkey")
    groups = []
    for m in parts[:-1]:
        if m not in MODIFIERS:
            raise ValueError(f"unknown modifier {m!r} (use {', '.join(MODIFIERS)})")
        groups.append({ecodes.ecodes[n] for n in MODIFIERS[m]})
    name = parts[-1].upper()
    name = name if name.startswith("KEY_") else "KEY_" + name
    code = ecodes.ecodes.get(name)
    if not isinstance(code, int):
        raise ValueError(f"unknown key {parts[-1]!r}")
    return groups, code


class Source:
    """One grabbed physical device, its local clone, and what the machine
    currently being controlled believes about it."""
    __slots__ = ("id", "dev", "ui", "desc", "frame", "held", "down", "swallow", "slot", "touches")

    def __init__(self, id_, dev, ui, desc, down, slot):
        self.id, self.dev, self.ui, self.desc = id_, dev, ui, desc
        self.frame = []          # events of the frame being assembled
        self.held = set()        # keys/buttons the current target has seen go down
        self.down = down         # keys physically down
        self.swallow = False     # a consumed hotkey press is still down
        self.slot = slot         # current multitouch slot (None: not a touchpad)
        self.touches = set()     # multitouch slots the current target has seen begin


class Sharer:
    """Holds every physical device grabbed; routes events to local uinput
    clones or to the remote machine."""

    def __init__(self, evdev, hotkey_name, host, explicit=None, notify=True):
        self.evdev = evdev
        self.e = e = evdev.ecodes
        self.hotkey_name = hotkey_name
        self.mod_groups, self.trigger = parse_hotkey(hotkey_name, e)
        self.hotkey_mods = set().union(*self.mod_groups) if self.mod_groups else set()
        self.all_mods = {e.ecodes[n] for names in MODIFIERS.values() for n in names}
        self.types = set(allowed_types(e))
        self.host = host
        self.explicit = explicit
        self.notifier = shutil.which("notify-send") if notify else None
        self.sources = {}                       # device id -> Source
        self.rejected = set()                   # paths we looked at and won't share
        self.busy = {}                          # path -> scans skipped because a key was down
        self.remote = False
        self.writer = None
        self.loop = None

    # -- feedback ---------------------------------------------------------- #
    def notify(self, text):
        log(text)
        if self.notifier:
            try:
                subprocess.Popen(
                    [self.notifier, "-a", "sharies", "-t", "1500", "-h", "int:transient:1",
                     "-h", "string:x-canonical-private-synchronous:sharies", "sharies", text],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except OSError:
                self.notifier = None

    # -- device management ------------------------------------------------- #
    def scan(self, first=False):
        """Grab keyboards/mice that have appeared; forget paths that are gone."""
        paths = [p for p in self.explicit if os.path.exists(p)] if self.explicit else event_nodes()
        self.rejected &= set(paths)
        open_paths = {s.dev.path for s in self.sources.values()}
        denied = 0
        for p in paths:
            if p in self.rejected or p in open_paths or len(self.sources) >= MAX_DEVICES:
                continue
            try:
                dev = self.evdev.InputDevice(p)
            except PermissionError:             # also: udev hasn't set permissions yet
                denied += 1
                continue
            except OSError:
                continue
            try:
                if is_clone(dev) or not (self.explicit or is_shareable(dev, self.e)):
                    self.rejected.add(p)
                elif dev.active_keys() and self.busy.get(p, 0) < 5:
                    # Grabbing while a key is down (e.g. the Enter that started
                    # us) would leave it stuck on the desktop: try again shortly.
                    self.busy[p] = self.busy.get(p, 0) + 1
                else:
                    self.busy.pop(p, None)
                    self.add(dev)
                    continue
            except Exception as exc:
                log(f"not sharing {p} ({dev.name}): {exc}")
                self.rejected.add(p)
            dev.close()
        if first and not self.sources and not self.busy:
            if denied:
                sys.exit("cannot open any input device. " + PERMISSION_HINT)
            log("no keyboard or mouse found yet; waiting for one to be connected")

    def add(self, dev):
        e = self.e
        dev.grab()
        try:
            led = {e.EV_LED: e.LED_MAX}
            ui, _ = build_uinput(self.evdev, describe(dev, e, led), led)
            caps = dev.capabilities(absinfo=True)
            slot = next((ai.value for c, ai in caps.get(e.EV_ABS, []) if c == e.ABS_MT_SLOT), None)
            desc = json.dumps(describe(dev, e)).encode()
            src = Source(min(set(range(MAX_DEVICES)) - set(self.sources)), dev, ui, desc,
                         set(dev.active_keys()), slot)
        except Exception:
            dev.ungrab()
            raise
        self.sources[src.id] = src
        self.loop.add_reader(dev.fd, self.on_readable, src)
        if e.EV_LED in caps:
            self.loop.add_reader(ui.fd, self.on_led, src)
        log(f"sharing {dev.path}: {dev.name}")
        self.announce(src)
        try:
            self.enter(src)
        except OSError as exc:
            self.drop(src, f"I/O error: {exc}", reject=True)

    def drop(self, src, why, reject=False):
        """Stop sharing a device and hand it back to the desktop (if it still exists)."""
        if self.sources.get(src.id) is not src:
            return
        log(f"no longer sharing {src.dev.path} ({src.dev.name}): {why}")
        if reject:
            self.rejected.add(src.dev.path)
        self.loop.remove_reader(src.dev.fd)
        self.loop.remove_reader(src.ui.fd)
        try:
            self.release(src)
        except OSError:
            pass
        del self.sources[src.id]
        self.send(REC.pack(CTRL, OP_REMOVE, src.id, 0))
        for close in (src.dev.ungrab, src.dev.close, src.ui.close):
            try:
                close()
            except Exception:
                pass

    def announce(self, src):
        self.send(REC.pack(CTRL, OP_ADD, src.id, len(src.desc)) + src.desc)

    # -- routing ----------------------------------------------------------- #
    def send(self, data):
        w = self.writer
        if w is None:
            return
        w.write(data)
        if w.transport.get_write_buffer_size() > MAX_BACKLOG:
            log("the link has stalled; dropping the connection")
            self.writer = None
            w.transport.abort()

    def flush(self, src):
        """Deliver the assembled frame to whichever machine is being controlled."""
        frame, src.frame = src.frame, []
        if not self.remote:
            inject(src.ui, frame)
        elif self.writer is not None:
            i, pack = src.id, REC.pack
            self.send(b"".join([pack(i, t, c, v) for t, c, v in frame]) + pack(i, 0, 0, 0))

    def release(self, src):
        """Make the current target let go of everything this device holds."""
        e = self.e
        frame = [(e.EV_KEY, k, 0) for k in src.held]
        for s in src.touches:
            frame += [(e.EV_ABS, e.ABS_MT_SLOT, s), (e.EV_ABS, e.ABS_MT_TRACKING_ID, -1)]
        src.held.clear()
        src.touches.clear()
        src.frame = frame
        if frame:
            self.flush(src)

    def enter(self, src):
        """Tell the (new) current target which multitouch slot is selected."""
        if src.slot is not None:
            src.frame = [(self.e.EV_ABS, self.e.ABS_MT_SLOT, src.slot)]
            self.flush(src)

    def each(self, step):
        for src in list(self.sources.values()):
            try:
                step(src)
            except OSError as exc:
                self.drop(src, f"I/O error: {exc}")

    def set_remote(self, remote, note=""):
        if remote == self.remote:
            return
        self.each(self.release)             # on the machine we are leaving
        self.remote = remote
        self.each(self.enter)               # on the machine we are entering
        self.notify(note + (f"Controlling {self.host}" if remote else "Controlling this computer"))

    def toggle(self):
        if self.remote:
            self.set_remote(False)
        elif self.writer is not None:
            self.set_remote(True)
        else:
            self.notify(f"Not connected to {self.host}")

    # -- input ------------------------------------------------------------- #
    def combo_held(self):
        """True if exactly the hotkey's modifiers (and no others) are down."""
        mods = set().union(*(s.down for s in self.sources.values())) & self.all_mods
        return mods <= self.hotkey_mods and all(g & mods for g in self.mod_groups)

    def on_readable(self, src):
        try:
            for ev in src.dev.read():
                self.handle(src, ev.type, ev.code, ev.value)
        except BlockingIOError:
            pass
        except OSError as exc:
            self.drop(src, f"disconnected ({exc.strerror or exc})")
        except Exception as exc:        # never leave a grabbed device dead
            self.drop(src, f"internal error: {exc!r}", reject=True)

    def unscan(self, src):
        """Drop the scancode that announced a key event we are not forwarding."""
        if src.frame and src.frame[-1][0] == self.e.EV_MSC:
            src.frame.pop()

    def handle(self, src, t, c, v):
        e = self.e
        if t == e.EV_SYN:
            if c == e.SYN_REPORT:
                if src.frame:
                    self.flush(src)
            elif c == e.SYN_DROPPED:
                self.resync(src)
            return
        if t not in self.types:
            return
        if t == e.EV_KEY:
            if v == 1:
                src.down.add(c)
            elif v == 0:
                src.down.discard(c)
            if c == self.trigger:
                if src.swallow:                     # repeats/release of a consumed press
                    src.swallow = v != 0
                    return self.unscan(src)
                if v == 1 and self.combo_held():
                    src.swallow = True
                    self.unscan(src)
                    if src.frame:
                        self.flush(src)
                    return self.toggle()
            if v == 1:
                src.held.add(c)
            elif c not in src.held:                 # pressed before a switch: the
                return self.unscan(src)             # target never saw it go down
            elif v == 0:
                src.held.discard(c)
        elif t == e.EV_ABS and src.slot is not None and c >= e.ABS_MT_SLOT:
            if c == e.ABS_MT_SLOT:
                src.slot = v
            elif c == e.ABS_MT_TRACKING_ID and v >= 0:
                src.touches.add(src.slot)
            elif src.slot not in src.touches:       # touch began before a switch
                return
            elif c == e.ABS_MT_TRACKING_ID:
                src.touches.discard(src.slot)
        src.frame.append((t, c, v))

    def resync(self, src):
        """The kernel dropped events for this device: release what is no longer down."""
        now = set(src.dev.active_keys())
        gone = src.held - now
        src.down, src.held = now, src.held & now
        src.swallow = src.swallow and self.trigger in now
        src.frame = [(self.e.EV_KEY, k, 0) for k in gone]
        if src.frame:
            self.flush(src)

    def on_led(self, src):
        """Show the local desktop's Caps/Num Lock state on the physical keyboard."""
        try:
            for ev in src.ui.read():
                if ev.type == self.e.EV_LED:
                    src.dev.set_led(ev.code, ev.value)
        except (BlockingIOError, OSError):
            pass
        except Exception:
            self.loop.remove_reader(src.ui.fd)

    # -- tasks ------------------------------------------------------------- #
    async def rescan(self):
        while True:
            await asyncio.sleep(SCAN_EVERY)
            try:
                self.scan()
            except Exception as exc:
                log(f"device scan failed: {exc!r}")

    async def heartbeat(self):
        while True:
            self.send(REC.pack(PING, 0, 0, 0))
            await asyncio.sleep(HEARTBEAT_EVERY)

    async def session(self, reader, writer, peer_der):
        """Run one connection; returns when it ends. Raises if setup fails."""
        if not peer_matches(writer, peer_der):
            raise ConnectionError("the receiver presented an unexpected certificate")
        writer.write(REC.pack(CTRL, OP_HELLO, PROTO_VERSION, 0))
        try:
            ack = await asyncio.wait_for(reader.readexactly(1), 10)
        except (asyncio.IncompleteReadError, ssl.SSLError, ConnectionError) as exc:
            raise ConnectionError(f"the receiver refused the session ({tls_reason(exc)}). "
                                  "The receiver's window shows its side of the story") from exc
        if ack != ACK_OK:
            raise ConnectionError("the receiver runs a different sharies version; "
                                  "install the same sharies.py on both machines")
        self.writer = writer
        for src in self.sources.values():
            self.announce(src)
        log(f"connected to {self.host}. Press {self.hotkey_name} to switch.")
        hb = asyncio.create_task(self.heartbeat())
        try:
            while True:
                await asyncio.wait_for(reader.readexactly(1), HEARTBEAT_TIMEOUT)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, OSError, ssl.SSLError):
            pass
        finally:
            hb.cancel()
            self.writer = None
            self.set_remote(False, f"Connection to {self.host} lost. ")

    async def run(self, port, ctx, peer_der):
        self.loop = asyncio.get_running_loop()
        self.scan(first=True)
        self.scanner = asyncio.create_task(self.rescan())  # keep a reference
        problem = None
        while True:
            writer = None
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.host, port, ssl=ctx, server_hostname=self.host), 10)
                await self.session(reader, writer, peer_der)
                problem = None
                log("disconnected; reconnecting")
            except (OSError, ssl.SSLError, asyncio.TimeoutError) as exc:
                msg = str(exc) if isinstance(exc, ConnectionError) and exc.args else tls_reason(exc)
                if msg != problem:                          # say it once, not every 2 s
                    log(f"cannot connect to {self.host}:{port}: {msg}. Will keep trying.")
                    problem = msg
            finally:
                if writer is not None:
                    writer.transport.abort()
            await asyncio.sleep(RETRY_EVERY)


def cmd_share(args):
    evdev = load_evdev()
    try:
        parse_hotkey(args.hotkey, evdev.ecodes)
    except ValueError as exc:
        sys.exit(f"bad --hotkey {args.hotkey!r}: {exc}. Examples: ctrl+shift+slash, ctrl+alt+k, f12")
    if not os.access("/dev/uinput", os.R_OK | os.W_OK):
        sys.exit("no read/write access to /dev/uinput (see README: udev rule + group)")
    for p in args.device or []:
        if not os.path.exists(p):
            log(f"{p} does not exist (yet); it will be shared when it appears")
    ctx, peer_der = make_ctx(False, Path(args.dir), peer_cert_path(args))
    sharer = Sharer(evdev, args.hotkey, args.host, args.device, not args.no_notify)
    asyncio.run(sharer.run(args.port, ctx, peer_der))


# --------------------------------------------------------------------------- #
# Receive side (listens, injects with uinput)
# --------------------------------------------------------------------------- #
class Receiver:
    def __init__(self, evdev, peer_der):
        self.evdev = evdev
        self.peer_der = peer_der
        self.ctx = None                     # set when we do the TLS handshake ourselves
        self.current = None                 # task of the running session

    def add(self, devs, i, body):
        self.remove(devs, i)
        try:
            ui, allowed = build_uinput(self.evdev, json.loads(body))
        except Exception as exc:            # skip this device, keep the session
            log(f"  cannot create device {i}: {exc!r}")
            return
        devs[i] = (ui, allowed, [])
        log(f"  + {ui.name}")

    def remove(self, devs, i):
        d = devs.pop(i, None)
        if d is not None:
            log(f"  - {d[0].name}")
            try:
                d[0].close()                # destroying the device releases its keys
            except OSError:
                pass

    def parse(self, buf, devs, writer):
        """Consume complete records from buf; return how many bytes were used."""
        pos, n, size = 0, len(buf), REC.size
        while n - pos >= size:
            i, t, c, v = REC.unpack_from(buf, pos)
            if i < CTRL:
                d = devs.get(i)
                if d is not None:
                    ui, allowed, frame = d
                    if t == 0:                              # EV_SYN
                        if c == 0 and frame:                # SYN_REPORT
                            inject(ui, frame)
                            frame.clear()
                    elif (t, c) in allowed:
                        if len(frame) >= MAX_FRAME:
                            raise ValueError("oversized frame")
                        frame.append((t, c, v))
            elif i == PING:
                writer.write(PONG)
            elif t == OP_ADD:
                if c >= MAX_DEVICES or not 0 < v <= MAX_DESC:
                    raise ValueError("bad device announcement")
                if n - pos - size < v:
                    break                                   # description not complete yet
                self.add(devs, c, bytes(buf[pos + size:pos + size + v]))
                pos += v
            elif t == OP_REMOVE:
                self.remove(devs, c)
            else:
                raise ValueError("unknown control message")
            pos += size
        return pos

    async def session(self, reader, writer, addr):
        loop = asyncio.get_running_loop()
        last = [loop.time()]

        async def watchdog():               # the sharer pings every second
            while loop.time() - last[0] < HEARTBEAT_TIMEOUT:
                await asyncio.sleep(HEARTBEAT_EVERY)
            log(f"{addr} stopped responding")
            writer.transport.abort()

        devs = {}                           # device id -> (uinput, allowed codes, frame)
        wd = asyncio.create_task(watchdog())
        try:
            i, op, version, _ = REC.unpack(await reader.readexactly(REC.size))
            if (i, op, version) != (CTRL, OP_HELLO, PROTO_VERSION):
                writer.write(ACK_BAD_VERSION)
                raise ValueError("the sharer runs a different sharies version; "
                                 "install the same sharies.py on both machines")
            writer.write(ACK_OK)
            log(f"session from {addr} started")
            buf = bytearray()
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                last[0] = loop.time()
                buf += data
                del buf[:self.parse(buf, devs, writer)]
        finally:
            wd.cancel()
            for i in list(devs):
                self.remove(devs, i)

    async def handle(self, reader, writer):
        addr = (writer.get_extra_info("peername") or ("?",))[0]
        if self.ctx is not None:            # handshake here, so a refusal can say why
            try:
                await asyncio.wait_for(writer.start_tls(self.ctx), 10)
            except Exception as exc:
                why = tls_reason(exc)
                log(f"refused {addr}: TLS handshake failed ({why}). {TLS_HINTS.get(why, '')}".rstrip())
                writer.transport.abort()
                return
        if not peer_matches(writer, self.peer_der):
            log(f"refused {addr}: it presented an unexpected certificate")
            writer.close()
            return
        task = asyncio.current_task()
        old, self.current = self.current, task
        try:
            if old is not None:             # the sharer reconnected: retire the stale session
                old.cancel()
                await asyncio.wait([old])
            await self.session(reader, writer, addr)
        except asyncio.CancelledError:      # replaced by a newer session, or shutting down
            pass
        except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError):
            pass
        except (ValueError, OSError) as exc:
            log(f"session from {addr} aborted: {exc}")
        finally:
            if self.current is task:
                self.current = None
            writer.close()
            log(f"session from {addr} ended")

    async def serve(self, bind, port, ctx):
        if hasattr(asyncio.StreamWriter, "start_tls"):     # Python 3.11+
            self.ctx, tls = ctx, {}
        else:
            tls = dict(ssl=ctx, ssl_handshake_timeout=10)
        try:
            server = await asyncio.start_server(self.handle, bind, port, **tls)
        except OSError as exc:
            sys.exit(f"cannot listen on port {port}: {exc}")
        log(f"listening on {bind or 'all interfaces'}, port {port}")
        async with server:
            await server.serve_forever()


def cmd_receive(args):
    evdev = load_evdev()
    if not os.access("/dev/uinput", os.R_OK | os.W_OK):
        sys.exit("no read/write access to /dev/uinput (see README: udev rule + group)")
    ctx, peer_der = make_ctx(True, Path(args.dir), peer_cert_path(args))
    asyncio.run(Receiver(evdev, peer_der).serve(args.bind, args.port, ctx))


# --------------------------------------------------------------------------- #
def main():
    p = argparse.ArgumentParser(prog="sharies", description=__doc__.split("\n\n")[0])
    p.add_argument("--dir", default=str(DEFAULT_DIR), help="key directory (default: %(default)s)")
    sub = p.add_subparsers(dest="cmd", required=True)
    peer_help = "the other machine's cert.pem (default: peer.pem in the key directory)"

    g = sub.add_parser("genkey", help="create this machine's key + certificate")
    g.add_argument("--force", action="store_true")
    g.set_defaults(fn=cmd_genkey)

    f = sub.add_parser("fingerprint", help="show this machine's and the peer's certificate fingerprints")
    f.add_argument("--peer-cert", help=peer_help)
    f.set_defaults(fn=cmd_fingerprint)

    sub.add_parser("list", help="show devices that would be shared").set_defaults(fn=cmd_list)

    s = sub.add_parser("share", help="send this machine's keyboard/mouse to HOST")
    s.add_argument("host")
    s.add_argument("--peer-cert", help=peer_help)
    s.add_argument("--port", type=int, default=DEFAULT_PORT)
    s.add_argument("--hotkey", default=DEFAULT_HOTKEY,
                   help="switch combo, e.g. ctrl+shift+slash, ctrl+alt+k, f12 (default: %(default)s)")
    s.add_argument("--device", action="append",
                   help="share only this device; repeatable. Prefer stable /dev/input/by-id/... paths "
                        "(default: every keyboard, mouse and touchpad)")
    s.add_argument("--no-notify", action="store_true", help="no desktop notification when switching")
    s.set_defaults(fn=cmd_share)

    r = sub.add_parser("receive", help="accept keyboard/mouse from the sharing machine")
    r.add_argument("--peer-cert", help=peer_help)
    r.add_argument("--bind", help="address to listen on (default: all interfaces)")
    r.add_argument("--port", type=int, default=DEFAULT_PORT)
    r.set_defaults(fn=cmd_receive)

    args = p.parse_args()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: sys.exit(0))
    args.fn(args)


if __name__ == "__main__":
    main()
