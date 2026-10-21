#!/usr/bin/env python3
"""
spdm-demo: interactive TUI front-end for spdm-req-tool.

Runs spdm-req-tool (locally or on a BMC over SSH) in JSON mode and shows the
SPDM conversation live as a colored, expandable tree:

    run  >  step (GET_CERTIFICATE ...)  >  message (--> GET_CERTIFICATE)
                                            >  decoded fields / raw hex
                                        >  result (verification, chain, ...)

Only the Python standard library is used.

Examples:
    spdm-demo.py --ssh root@10.0.0.120 --password 0penBmc -e 42
    spdm-demo.py --local -e 42                 # tool runs on this machine
    spdm-demo.py --replay session.jsonl        # offline replay of a recording
"""

import argparse
import curses
import json
import locale
import os
import queue
import shlex
import shutil
import subprocess
import sys
import textwrap
import threading
import time

# --------------------------------------------------------------------------
# Tree model
# --------------------------------------------------------------------------

# Color roles (mapped to curses pairs in the UI, ANSI in --snapshot).
C_NORMAL, C_KEY, C_OK, C_WARN, C_ERR, C_DIM, C_HI, C_REQ, C_RSP, C_STEP, C_RUN, C_SESSION = range(12)

STYLE_ROLE = {"ok": C_OK, "warn": C_WARN, "err": C_ERR, "hex": C_DIM, "hi": C_HI}
STATUS_BADGE = {
    "ok": (" OK ", C_OK), "warn": ("WARN", C_WARN), "fail": ("FAIL", C_ERR),
    "skip": ("SKIP", C_DIM), "run": (" .. ", C_HI),
}

HEX_INLINE = 48  # hex chars shown inline before folding into rows


class Node:
    __slots__ = ("segs", "children", "expanded", "parent", "detail", "kind")

    def __init__(self, segs, parent=None, expanded=False, detail=None, kind=""):
        self.segs = segs            # list of (text, role)
        self.children = []
        self.expanded = expanded
        self.parent = parent
        self.detail = detail        # full text for the detail pane
        self.kind = kind

    def add(self, node):
        node.parent = self
        self.children.append(node)
        return node

    def text(self):
        return "".join(t for t, _ in self.segs)


def hex_rows(hexstr, per_row=32):
    """'0011..' -> ['0000: 00 11 ...', ...] with 32 bytes per row."""
    rows = []
    n = per_row * 2
    for off in range(0, len(hexstr), n):
        chunk = hexstr[off:off + n]
        spaced = " ".join(chunk[i:i + 2] for i in range(0, len(chunk), 2))
        rows.append("%04x: %s" % (off // 2, spaced))
    return rows


def tree_from_json(items, parent, depth=0, expand_depth=0):
    """Convert the tool's {"k","v","s","c"} tree into Nodes."""
    for it in items or []:
        key = it.get("k", "")
        val = it.get("v")
        role = STYLE_ROLE.get(it.get("s"), C_NORMAL)
        kids = it.get("c")
        if val is None:
            segs = [(key, C_HI if role == C_NORMAL else role)]
        elif it.get("s") == "hex" and len(val) > HEX_INLINE:
            segs = [(key, C_KEY), (": ", C_NORMAL),
                    (val[:HEX_INLINE] + "…", C_DIM), ("  (%d bytes)" % (len(val) // 2), C_DIM)]
        else:
            segs = [(key, C_KEY), (": ", C_NORMAL), (val, role)]
        detail = "%s: %s" % (key, val) if val is not None else key
        n = parent.add(Node(segs, expanded=depth < expand_depth, detail=detail))
        if it.get("s") == "hex" and val and len(val) > HEX_INLINE:
            for row in hex_rows(val):
                n.add(Node([(row, C_DIM)], detail=row))
        if kids:
            tree_from_json(kids, n, depth + 1, expand_depth)


class Model:
    """Builds the tree from tool events."""

    def __init__(self):
        self.root = Node([("root", C_NORMAL)], expanded=True)
        self.run = None
        self.step = None
        self.stats = {}
        self.runs = 0
        self.mctp = [0, 0]
        self.done = None

    def start_run(self, title):
        for r in self.root.children:     # fold older runs
            r.expanded = False
        self.runs += 1
        self.run = self.root.add(Node([("Run #%d " % self.runs, C_RUN), (title, C_RUN)],
                                      expanded=True, kind="run", detail=title))
        self.step = None
        self.mctp = [0, 0]
        self.done = None
        return self.run

    def _container(self):
        return self.step or self.run or self.root

    def log(self, level, msg):
        role = {"fail": C_ERR, "warn": C_WARN, "ok": C_DIM}.get(level, C_DIM)
        prefix = {"fail": "error: ", "warn": "warning: "}.get(level, "")
        self._container().add(Node([(prefix + msg, role)], detail=prefix + msg))

    def event(self, ev):
        kind = ev.get("ev")
        if kind == "banner":
            # A recording may hold several runs: start a new one per tool banner.
            if self.run is None or self.done is not None or \
                    any(c.kind == "step" for c in self.run.children):
                self.start_run("recorded run")
            self.run.add(Node([(ev.get("msg", ""), C_DIM)], detail=ev.get("msg")))
        elif kind == "step_begin":
            for s in self.run.children:          # keep finished steps tidy
                if s.kind == "step":
                    s.expanded = False
            badge, role = STATUS_BADGE["run"]
            self.step = self.run.add(Node(
                [("[", C_NORMAL), (badge, role), ("] ", C_NORMAL), (ev.get("title", ""), C_STEP)],
                expanded=True, kind="step", detail=ev.get("title")))
            self.step.detail = ev.get("title", "")
        elif kind == "msg":
            self._msg(ev)
        elif kind == "mctp":
            self.mctp[0 if ev.get("dir") == "tx" else 1] += 1
        elif kind == "step_end":
            self._step_end(ev)
        elif kind == "log":
            self.log(ev.get("level"), ev.get("msg", ""))
        elif kind == "done":
            self.done = ev
            st = ev.get("status", "?")
            badge, role = STATUS_BADGE.get(st, ("?", C_NORMAL))
            self.run.segs = self.run.segs + [("   [", C_NORMAL), (badge, role), ("] ", C_NORMAL),
                                             ("%d passed, %d warn, %d failed" % (
                                                 ev.get("passed", 0), ev.get("warned", 0),
                                                 ev.get("failed", 0)), C_DIM)]
            self.step = None

    def _msg(self, ev):
        req = ev.get("dir") == "req"
        name = ev.get("name", "?")
        segs = [("→ " if req else "← ", C_REQ if req else C_RSP),
                (name, C_ERR if name.startswith("ERROR") else (C_REQ if req else C_RSP)),
                ("  v%s  %d B" % (ev.get("ver", "?"), ev.get("len", 0)), C_DIM)]
        if ev.get("session"):
            segs.append(("  [secured %s]" % ev["session"], C_SESSION))
        m = self._container().add(Node(segs, kind="msg",
                                       detail="%s %s (%d bytes)%s" % (
                                           "Request" if req else "Response", name,
                                           ev.get("len", 0),
                                           " in secured session %s" % ev["session"]
                                           if ev.get("session") else "")))
        tree_from_json(ev.get("tree"), m)
        hexstr = ev.get("hex", "")
        if hexstr:
            raw = m.add(Node([("Raw bytes", C_HI), ("  (%d)" % (len(hexstr) // 2), C_DIM)],
                             detail="raw message bytes"))
            for row in hex_rows(hexstr, 16):
                raw.add(Node([(row, C_DIM)], detail=row))

    def _step_end(self, ev):
        st = ev.get("status", "?")
        badge, role = STATUS_BADGE.get(st, ("?", C_NORMAL))
        if self.step is None:
            self.event({"ev": "step_begin", "title": ev.get("id", "")})
        step = self.step
        title = step.segs[-1][0]
        step.segs = [("[", C_NORMAL), (badge, role), ("] ", C_NORMAL), (title, C_STEP)]
        summary = ev.get("summary", "")
        step.detail = "%s\n%s" % (title, summary)
        step.add(Node([("↳ ", role), (summary, role)], detail=summary))
        result = ev.get("result") or []
        if result:
            res = step.add(Node([("Result", C_HI)], expanded=True, detail="step result"))
            tree_from_json(result, res, 0, expand_depth=1)
        # Folded unless something needs attention.
        step.expanded = st in ("fail", "warn")
        self.stats[st] = self.stats.get(st, 0) + 1
        self.step = None


def visible(node, depth=0, out=None):
    if out is None:
        out = []
    for c in node.children:
        out.append((c, depth))
        if c.expanded and c.children:
            visible(c, depth + 1, out)
    return out


def set_expanded(node, value, recursive=True):
    node.expanded = value
    if recursive:
        for c in node.children:
            set_expanded(c, value, True)


# --------------------------------------------------------------------------
# Tool runner
# --------------------------------------------------------------------------

class Runner:
    def __init__(self, args):
        self.args = args
        self.proc = None
        self.q = queue.Queue()
        self.record = open(args.record, "a") if args.record else None

    def command(self, cmds, extra):
        a = self.args
        tool = [a.tool, "-j", "-e", str(a.eid)] + extra + a.tool_args + cmds
        if a.local:
            return tool
        ssh = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
               "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=5", a.ssh, shlex.join(tool)]
        if a.password:
            if not shutil.which("sshpass"):
                raise RuntimeError("--password needs sshpass installed")
            ssh = ["sshpass", "-p", a.password] + ssh
        return ssh

    def busy(self):
        return self.proc is not None and self.proc.poll() is None

    def start(self, cmds, extra):
        argv = self.command(cmds, extra)
        self.proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     stdin=subprocess.DEVNULL, text=True, bufsize=1)
        threading.Thread(target=self._pump, args=(self.proc.stdout, False), daemon=True).start()
        threading.Thread(target=self._pump, args=(self.proc.stderr, True), daemon=True).start()
        return argv

    def _pump(self, stream, is_err):
        for line in stream:
            line = line.rstrip("\n")
            if not line:
                continue
            if is_err:
                self.q.put({"ev": "log", "level": "fail", "msg": line})
                continue
            if self.record:
                self.record.write(line + "\n")
                self.record.flush()
            try:
                self.q.put(json.loads(line))
            except ValueError:
                self.q.put({"ev": "log", "level": "warn", "msg": line})

    def stop(self):
        if self.busy():
            self.proc.terminate()


def replay_events(path):
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except ValueError:
                    pass


# --------------------------------------------------------------------------
# Scenarios
# --------------------------------------------------------------------------

SCENARIOS = [
    ("1", "Version", ["version"], "GET_VERSION"),
    ("2", "Connect (VCA)", ["connect"], "VERSION / CAPABILITIES / ALGORITHMS"),
    ("3", "Digests", ["digests"], "certificate chain digests"),
    ("4", "Certificates", ["digests", "cert"], "GET_CERTIFICATE + chain verify"),
    ("5", "Get root CA", ["get-root-ca"], "save responder root CA"),
    ("6", "Challenge", ["challenge"], "authenticate responder"),
    ("7", "Measurements", ["meas"], "signed GET_MEASUREMENTS"),
    ("8", "Secure session", ["session"], "KEY_EXCHANGE / FINISH ..."),
    ("a", "Run all", ["all"], "full attestation flow"),
]

VERSIONS = [None, "1.0", "1.1", "1.2", "1.3", "1.4"]

HELP = [
    ("1-8, a", "run a scenario (a = all)"),
    ("r", "re-run the last scenario"),
    ("t", "toggle trust anchor (--root-ca)"),
    ("v", "cycle SPDM version (auto/1.0../1.4)"),
    ("Up/Down j/k", "move"),
    ("PgUp/PgDn", "page"),
    ("Right/l/Enter", "expand / toggle"),
    ("Left/h", "collapse / go to parent"),
    ("e / E", "expand subtree / expand everything"),
    ("c / C", "collapse subtree / collapse everything"),
    ("f", "follow live output on/off"),
    ("x", "kill a running command"),
    ("?", "this help"),
    ("q", "quit"),
]


class App:
    def __init__(self, args):
        self.args = args
        self.model = Model()
        self.runner = None if args.replay else Runner(args)
        self.cursor = 0
        self.top = 0
        self.follow = True
        self.trust = bool(args.trust)
        self.version_idx = 0
        self.last = None
        self.status = "Press 1-8 or 'a' to run a scenario, '?' for help"
        self.show_help = False
        self.spin = 0

    # ---------------------------------------------------------- actions
    def extra_args(self, cmds):
        extra = []
        if self.trust:
            extra += ["-r", self.args.root_ca]
        if "get-root-ca" in cmds:
            extra += ["-R", self.args.root_ca]
        v = VERSIONS[self.version_idx]
        if v:
            extra += ["-V", v]
        return extra

    def run_scenario(self, sc):
        if self.runner is None:
            self.status = "replay mode: running is disabled"
            return
        if self.runner.busy():
            self.status = "busy - wait for the current run or press x"
            return
        key, title, cmds, _ = sc
        extra = self.extra_args(cmds)
        self.model.start_run("%s  (%s)" % (title, " ".join(extra + cmds)))
        try:
            argv = self.runner.start(cmds, extra)
            self.model.run.detail = " ".join(shlex.quote(a) if a != self.args.password else "***"
                                             for a in argv)
        except Exception as e:  # noqa: BLE001 - shown to the user
            self.model.log("fail", str(e))
        self.last = sc
        self.follow = True
        self.status = "running: %s" % title

    def poll(self):
        changed = False
        if self.runner:
            while True:
                try:
                    ev = self.runner.q.get_nowait()
                except queue.Empty:
                    break
                if self.model.run is None:
                    self.model.start_run("output")
                self.model.event(ev)
                changed = True
            if self.last and not self.runner.busy() and self.status.startswith("running") \
                    and self.runner.q.empty():
                d = self.model.done
                if d:
                    self.status = "finished: %d passed, %d warnings, %d failed" % (
                        d.get("passed", 0), d.get("warned", 0), d.get("failed", 0))
                else:
                    self.status = "command exited (rc=%s)" % self.runner.proc.returncode
                changed = True
        if changed and self.follow:
            self.cursor = len(visible(self.model.root)) - 1
        return changed

    # ---------------------------------------------------------- render
    def header_lines(self, width):
        a = self.args
        target = "local" if a.local else ("replay " + a.replay if a.replay else "ssh " + a.ssh)
        v = VERSIONS[self.version_idx] or "auto"
        line1 = [(" SPDM Requester Demo ", C_RUN), ("  libspdm over AF_MCTP", C_DIM)]
        line2 = [(" target: ", C_DIM), (target, C_HI), ("   EID: ", C_DIM), (str(a.eid), C_HI),
                 ("   SPDM: ", C_DIM), (v, C_HI), ("   trust anchor: ", C_DIM),
                 (("ON " + a.root_ca) if self.trust else "off", C_OK if self.trust else C_WARN)]
        return [line1, line2]

    def footer(self):
        busy = self.runner is not None and self.runner.busy()
        spin = "|/-\\"[self.spin % 4] if busy else " "
        m = self.model
        return [(" %s " % spin, C_HI), (self.status, C_NORMAL),
                ("   mctp tx/rx %d/%d" % (m.mctp[0], m.mctp[1]), C_DIM),
                ("   follow:%s" % ("on" if self.follow else "off"), C_DIM),
                ("   ? help  q quit", C_DIM)]

    def menu_lines(self):
        out = [[(" Scenarios", C_HI)]]
        for key, title, _, desc in SCENARIOS:
            out.append([(" %s " % key, C_REQ), (title, C_NORMAL)])
            out.append([("    " + desc, C_DIM)])
        return out

    def tree_lines(self, width):
        vis = visible(self.model.root)
        lines = []
        glyph_open, glyph_closed, glyph_leaf = (("▾ ", "▸ ", "  ")
                                                if self.args.unicode else ("- ", "+ ", "  "))
        for node, depth in vis:
            g = glyph_leaf
            if node.children:
                g = glyph_open if node.expanded else glyph_closed
            lines.append((node, [("  " * depth, C_NORMAL), (g, C_DIM)] + node.segs))
        return lines


# --------------------------------------------------------------------------
# curses front-end
# --------------------------------------------------------------------------

def init_colors():
    curses.start_color()
    try:
        curses.use_default_colors()
        bg = -1
    except curses.error:
        bg = curses.COLOR_BLACK
    pairs = {
        C_NORMAL: (-1, bg), C_KEY: (curses.COLOR_CYAN, bg), C_OK: (curses.COLOR_GREEN, bg),
        C_WARN: (curses.COLOR_YELLOW, bg), C_ERR: (curses.COLOR_RED, bg),
        C_DIM: (curses.COLOR_WHITE, bg), C_HI: (-1, bg), C_REQ: (curses.COLOR_YELLOW, bg),
        C_RSP: (curses.COLOR_GREEN, bg), C_STEP: (curses.COLOR_BLUE, bg),
        C_RUN: (curses.COLOR_MAGENTA, bg), C_SESSION: (curses.COLOR_MAGENTA, bg),
    }
    attrs = {}
    for role, (fg, b) in pairs.items():
        curses.init_pair(role + 1, fg, b)
        a = curses.color_pair(role + 1)
        if role in (C_HI, C_STEP, C_RUN, C_ERR, C_OK, C_WARN, C_REQ, C_RSP):
            a |= curses.A_BOLD
        if role == C_DIM:
            a |= curses.A_DIM
        attrs[role] = a
    return attrs


def put(win, y, x, segs, width, attrs, extra=0):
    """Draw colored segments, clipped to width."""
    for text, role in segs:
        if x >= width:
            break
        text = text.replace("\t", " ")
        room = width - x
        if len(text) > room:
            text = text[:max(room - 1, 0)] + ("…" if room > 0 else "")
        try:
            win.addstr(y, x, text, attrs.get(role, 0) | extra)
        except curses.error:
            pass
        x += len(text)
    return x


def curses_main(stdscr, app):
    attrs = init_colors()
    curses.curs_set(0)
    stdscr.timeout(100)
    stdscr.keypad(True)

    if app.args.replay:
        app.model.start_run("replay of " + app.args.replay)
        for ev in replay_events(app.args.replay):
            app.model.event(ev)
        app.status = "replay loaded"
    elif app.args.autorun:
        sc = next((s for s in SCENARIOS if s[0] == app.args.autorun), None)
        if sc:
            app.run_scenario(sc)

    while True:
        app.poll()
        app.spin += 1
        h, w = stdscr.getmaxyx()
        stdscr.erase()
        hdr = app.header_lines(w)
        for i, segs in enumerate(hdr):
            put(stdscr, i, 0, segs, w, attrs)
        try:
            stdscr.hline(len(hdr), 0, curses.ACS_HLINE, w)
        except curses.error:
            pass
        body_top = len(hdr) + 1
        detail_h = 3
        body_h = max(h - body_top - detail_h - 2, 1)

        menu_w = 30 if w >= 100 else 0
        if menu_w:
            for i, segs in enumerate(app.menu_lines()[:body_h]):
                put(stdscr, body_top + i, 0, segs, menu_w - 1, attrs)
            for y in range(body_top, body_top + body_h):
                try:
                    stdscr.addch(y, menu_w - 1, curses.ACS_VLINE)
                except curses.error:
                    pass

        lines = app.tree_lines(w - menu_w)
        if lines:
            app.cursor = max(0, min(app.cursor, len(lines) - 1))
        if app.cursor < app.top:
            app.top = app.cursor
        if app.cursor >= app.top + body_h:
            app.top = app.cursor - body_h + 1
        for i in range(body_h):
            idx = app.top + i
            if idx >= len(lines):
                break
            node, segs = lines[idx]
            extra = curses.A_REVERSE if idx == app.cursor else 0
            if extra:
                try:
                    stdscr.addstr(body_top + i, menu_w, " " * max(w - menu_w - 1, 0),
                                  curses.A_REVERSE)
                except curses.error:
                    pass
            put(stdscr, body_top + i, menu_w, segs, w - 1, attrs, extra)
        if not lines:
            put(stdscr, body_top + 1, menu_w + 2,
                [("Nothing yet. Press ", C_DIM), ("a", C_REQ), (" to run the full attestation "
                                                               "flow, or 1-8 for one step.", C_DIM)],
                w - 1, attrs)

        # detail pane
        dy = body_top + body_h
        try:
            stdscr.hline(dy, 0, curses.ACS_HLINE, w)
        except curses.error:
            pass
        if lines:
            node = lines[app.cursor][0]
            text = node.detail or node.text()
            wrapped = []
            for para in text.split("\n"):
                wrapped += textwrap.wrap(para, max(w - 2, 10)) or [""]
            for i, l in enumerate(wrapped[:detail_h]):
                put(stdscr, dy + 1 + i, 1, [(l, C_NORMAL)], w - 1, attrs)
        put(stdscr, h - 1, 0, app.footer(), w - 1, attrs, curses.A_REVERSE)

        if app.show_help:
            draw_help(stdscr, attrs, h, w)
        stdscr.refresh()

        ch = stdscr.getch()
        if ch == -1:
            continue
        if app.show_help:
            app.show_help = False
            continue
        if not handle_key(app, ch, lines, body_h):
            break
    if app.runner:
        app.runner.stop()


def draw_help(stdscr, attrs, h, w):
    bw, bh = min(60, w - 4), min(len(HELP) + 4, h - 2)
    y0, x0 = (h - bh) // 2, (w - bw) // 2
    win = curses.newwin(bh, bw, y0, x0)
    win.erase()
    win.box()
    put(win, 0, 2, [(" Keys ", C_HI)], bw - 1, attrs)
    for i, (k, d) in enumerate(HELP[:bh - 4]):
        put(win, 2 + i, 2, [("%-14s" % k, C_REQ), (d, C_NORMAL)], bw - 2, attrs)
    win.refresh()


def handle_key(app, ch, lines, page):
    node = lines[app.cursor][0] if lines else None
    if ch in (ord("q"), ord("Q")):
        return False
    if ch == ord("?"):
        app.show_help = True
        return True
    for sc in SCENARIOS:
        if ch == ord(sc[0]):
            app.run_scenario(sc)
            return True
    if ch == ord("r") and app.last:
        app.run_scenario(app.last)
        return True
    if ch == ord("t"):
        app.trust = not app.trust
        app.status = "trust anchor %s" % ("ON: -r " + app.args.root_ca if app.trust else "off")
        return True
    if ch == ord("v"):
        app.version_idx = (app.version_idx + 1) % len(VERSIONS)
        app.status = "SPDM version: %s" % (VERSIONS[app.version_idx] or "auto")
        return True
    if ch == ord("x") and app.runner:
        app.runner.stop()
        return True
    if ch == ord("f"):
        app.follow = not app.follow
        return True
    if not lines:
        return True
    moved = True
    if ch in (curses.KEY_UP, ord("k")):
        app.cursor -= 1
    elif ch in (curses.KEY_DOWN, ord("j")):
        app.cursor += 1
    elif ch == curses.KEY_PPAGE:
        app.cursor -= page
    elif ch == curses.KEY_NPAGE:
        app.cursor += page
    elif ch in (curses.KEY_HOME, ord("g")):
        app.cursor = 0
    elif ch in (curses.KEY_END, ord("G")):
        app.cursor = len(lines) - 1
    elif ch in (curses.KEY_RIGHT, ord("l")):
        if node.children:
            if not node.expanded:
                node.expanded = True
            else:
                app.cursor += 1
    elif ch in (10, 13, curses.KEY_ENTER, ord(" ")):
        if node.children:
            node.expanded = not node.expanded
    elif ch in (curses.KEY_LEFT, ord("h")):
        if node.expanded and node.children:
            node.expanded = False
        elif node.parent is not None and node.parent is not app.model.root:
            app.cursor = next(i for i, (n, _) in enumerate(lines) if n is node.parent)
    elif ch == ord("e"):
        set_expanded(node, True)
    elif ch == ord("c"):
        set_expanded(node, False)
    elif ch == ord("E"):
        for c in app.model.root.children:
            set_expanded(c, True)
    elif ch == ord("C"):
        for c in app.model.root.children:
            set_expanded(c, False)
        app.cursor = 0
    else:
        moved = False
    if moved:
        app.follow = False
    return True


# --------------------------------------------------------------------------
# Headless snapshot (for scripts / CI): renders the tree as ANSI text
# --------------------------------------------------------------------------

ANSI = {C_NORMAL: "", C_KEY: "\033[36m", C_OK: "\033[1;32m", C_WARN: "\033[1;33m",
        C_ERR: "\033[1;31m", C_DIM: "\033[2m", C_HI: "\033[1m", C_REQ: "\033[1;33m",
        C_RSP: "\033[1;32m", C_STEP: "\033[1;34m", C_RUN: "\033[1;35m", C_SESSION: "\033[35m"}


def snapshot(app, expand, color):
    if expand == "all":
        for c in app.model.root.children:
            set_expanded(c, True)
    for _, segs in app.tree_lines(200):
        if color:
            print("".join(ANSI[r] + t + "\033[0m" for t, r in segs))
        else:
            print("".join(t for t, _ in segs))


def main():
    p = argparse.ArgumentParser(description="Interactive TUI demo for spdm-req-tool",
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog=__doc__.split("Examples:")[1])
    tgt = p.add_mutually_exclusive_group()
    tgt.add_argument("--ssh", default="root@10.0.0.120", help="run the tool on this host via SSH")
    tgt.add_argument("--local", action="store_true", help="run the tool on this machine")
    tgt.add_argument("--replay", metavar="FILE", help="show a recorded JSON-lines file")
    p.add_argument("--password", default=os.environ.get("BMC_PASS"),
                   help="SSH password (uses sshpass; default $BMC_PASS)")
    p.add_argument("--tool", default="/tmp/spdm-req-tool", help="path of spdm-req-tool on the target")
    p.add_argument("-e", "--eid", type=int, default=42, help="responder EID (default 42)")
    p.add_argument("--root-ca", default="/tmp/spdm-demo-rootca.pem",
                   help="root CA path on the target used by 'Get root CA' and the trust toggle")
    p.add_argument("--trust", action="store_true", help="start with the trust anchor enabled")
    p.add_argument("--record", metavar="FILE", help="append the raw JSON events to FILE")
    p.add_argument("--run", dest="autorun", metavar="KEY", help="start scenario KEY (1-8, a)")
    p.add_argument("--snapshot", choices=["folded", "all"],
                   help="no TUI: render the tree to stdout (with --replay or --run)")
    p.add_argument("--no-color", action="store_true", help="with --snapshot: plain text")
    p.add_argument("--ascii", action="store_true", help="ASCII glyphs only")
    p.add_argument("tool_args", nargs="*", help="extra spdm-req-tool options (after --)")
    args = p.parse_args()
    args.unicode = not args.ascii and "UTF-8" in (locale.getpreferredencoding(False) or "").upper()
    if args.replay:
        args.local = False

    app = App(args)
    if args.snapshot:
        if args.replay:
            app.model.start_run("replay of " + args.replay)
            for ev in replay_events(args.replay):
                app.model.event(ev)
        elif args.autorun:
            sc = next(s for s in SCENARIOS if s[0] == args.autorun)
            app.run_scenario(sc)
            while app.runner.busy() or not app.runner.q.empty():
                app.poll()
                time.sleep(0.05)
            time.sleep(0.2)
            app.poll()
        snapshot(app, args.snapshot, not args.no_color and sys.stdout.isatty())
        return 0

    locale.setlocale(locale.LC_ALL, "")
    os.environ.setdefault("ESCDELAY", "25")
    curses.wrapper(curses_main, app)
    return 0


if __name__ == "__main__":
    sys.exit(main())
