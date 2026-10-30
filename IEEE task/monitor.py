import os
import sys
import json
import time
import hmac
import hashlib
import re
import random
import shutil
from datetime import datetime
from collections import deque


# ============================================================
# 1. CONFIGURATION
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATABASE = os.path.join(BASE_DIR, "hashes.json")
SIGNATURE_FILE = os.path.join(BASE_DIR, "hashes.hmac")
LOG_FILE = os.path.join(BASE_DIR, "security_log.txt")

KEY_FILE = os.path.join(
    os.path.expanduser("~"),
    ".file_integrity_monitor",
    "secret.key"
)

SCAN_INTERVAL = 2.0     # files are re-scanned every 2 seconds
FRAME_DELAY = 0.25      # screen redraw rate (clock, glitter, colour flow)
CHUNK_SIZE = 65536
MAX_EVENTS = 8
MAX_FILE_ROWS = 10


# ============================================================
# 2. COLOURS  (black background + flowing purple glitter)
# ============================================================

RESET = "\033[0m"
BG = "\033[48;2;6;6;9m"          # rich black (true-colour)
BOLD = "\033[1m"


def fg(n):
    return f"\033[38;5;{n}m"


PURPLE = fg(183)   # lavender
VIOLET = fg(60)    # faint lines
GREEN = fg(121)    # mint
RED = fg(204)      # hot coral
ORANGE = fg(216)   # peach
CYAN = fg(117)     # baby blue
PINK = fg(213)
WHITE = fg(255)
GREY = fg(245)

# Colours that "flow" around the border.
FLOW = [183]   # one soft lavender border

SPARK_CHARS = "✦✧·*+"
SPARK_COLOURS = [231, 189, 225, 159, 229, 220]

os.system("")   # enables ANSI colours on Windows


# ============================================================
# 3. GLOBAL STATE
# ============================================================

scan_number = 0
start_time = time.monotonic()
last_scan_time = "--:--:--"

previous_status = {}
previous_database_error = False

event_history = deque(maxlen=MAX_EVENTS)


# ============================================================
# 4. TEXT HELPERS (all ANSI-aware)
# ============================================================

ANSI_RE = re.compile(r"(\033\[[0-9;]*m)")


def paint(text, *codes):
    """Colour text, then return to the black background."""
    return "".join(codes) + str(text) + RESET + BG


def visible_length(text):
    return len(ANSI_RE.sub("", str(text)))


def clip(text, width):
    """Cut text to `width` visible characters without breaking colours."""
    out = []
    used = 0

    for part in ANSI_RE.split(str(text)):

        if ANSI_RE.fullmatch(part):
            out.append(part)
            continue

        take = part[:max(0, width - used)]
        out.append(take)
        used += len(take)

    return "".join(out)


def pad(text, width):
    text = clip(text, width)
    return text + " " * (width - visible_length(text))


def shorten(text, length):
    text = str(text)

    if len(text) > length:
        return "..." + text[-(length - 3):]

    return text


def current_time():
    return datetime.now().strftime("%H:%M:%S")


def uptime():
    elapsed = int(time.monotonic() - start_time)
    return f"{elapsed // 3600:02}:{(elapsed % 3600) // 60:02}:{elapsed % 60:02}"


# ============================================================
# 5. EVENT LOGGING
# ============================================================

def log_event(level, message):

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"{timestamp} | {level} | {message}"

    try:
        with open(LOG_FILE, "a", encoding="utf-8") as file:
            file.write(entry + "\n")
    except OSError:
        pass

    event_history.append(entry)


def load_recent_events():

    try:
        if not os.path.exists(LOG_FILE):
            return

        with open(LOG_FILE, "r", encoding="utf-8") as file:
            lines = file.readlines()

        for line in lines[-MAX_EVENTS:]:
            entry = line.strip()
            if entry:
                event_history.append(entry)

    except OSError:
        pass


# ============================================================
# 6. SECRET KEY + HMAC-VERIFIED DATABASE
# ============================================================

def load_secret_key():

    if not os.path.exists(KEY_FILE):
        raise FileNotFoundError("Secret key missing. Run hash.py first.")

    with open(KEY_FILE, "rb") as file:
        key = file.read()

    if len(key) != 32:
        raise ValueError("Invalid secret key length.")

    return key


def generate_signature(hashes, key):

    data = json.dumps(
        hashes,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")

    return hmac.new(key, data, hashlib.sha256).hexdigest()


def load_verified_database(key):

    for attempt in range(3):

        try:

            with open(DATABASE, "r", encoding="utf-8") as file:
                hashes = json.load(file)

            with open(SIGNATURE_FILE, "r", encoding="utf-8") as file:
                stored_signature = file.read().strip()

            if not isinstance(hashes, dict):
                raise ValueError("Invalid database structure.")

            for path, stored_hash in hashes.items():

                if not isinstance(path, str):
                    raise ValueError("Invalid file path.")

                if (
                    not isinstance(stored_hash, str)
                    or len(stored_hash) != 64
                    or any(c not in "0123456789abcdefABCDEF"
                           for c in stored_hash)
                ):
                    raise ValueError(f"Invalid SHA-256 baseline: {path}")

            calculated = generate_signature(hashes, key)

            if not hmac.compare_digest(stored_signature, calculated):
                raise ValueError(
                    "HMAC authentication failed. "
                    "Database may have been modified."
                )

            return hashes, None

        except (OSError, ValueError, json.JSONDecodeError) as error:

            if attempt < 2:
                time.sleep(0.2)     # hash.py may be mid-write; retry
            else:
                return None, str(error)

    return None, "Database verification failed."


# ============================================================
# 7. HASHING + GROUPING
# ============================================================

def calculate_sha256(file_path):

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(CHUNK_SIZE)
            if not chunk:
                break
            sha256.update(chunk)

    return sha256.hexdigest()


def group_registered_files(hashes):

    grouped = {}

    for path, expected_hash in hashes.items():

        key = os.path.normcase(os.path.abspath(path))

        if key not in grouped:
            grouped[key] = {"path": path, "hashes": set()}

        grouped[key]["hashes"].add(expected_hash.lower())

    return grouped


# ============================================================
# 8. STATUS CHANGE DETECTION
# ============================================================

def record_status_change(path, state):

    key = os.path.normcase(os.path.abspath(path))
    old_state = previous_status.get(key)

    previous_status[key] = state

    if old_state == state:
        return

    if old_state is None and state == "SAFE":
        return

    if state in ("MODIFIED", "MISSING", "CONFLICT"):
        log_event("CRITICAL", f"{state} | {path}")

    elif state == "UNAVAILABLE":
        log_event("WARNING", f"{state} | {path}")

    elif state == "SAFE" and old_state is not None:
        log_event("INFO", f"FILE RESTORED | {path}")


# ============================================================
# 9. FILE SCANNING
# ============================================================

def scan_files(key):

    global scan_number, previous_database_error, last_scan_time

    scan_number += 1
    last_scan_time = current_time()

    hashes, error = load_verified_database(key)

    if error:

        if not previous_database_error:
            log_event("CRITICAL", f"DATABASE AUTHENTICATION FAILED | {error}")

        previous_database_error = True

        return {
            "database_ok": False, "error": error, "files": [],
            "safe": 0, "danger": 0, "warnings": 0, "registered": 0
        }

    if previous_database_error:
        log_event("INFO", "DATABASE AUTHENTICATION RESTORED")

    previous_database_error = False

    grouped = group_registered_files(hashes)

    for removed in set(previous_status) - set(grouped):
        log_event("INFO", f"REGISTRATION REMOVED | {removed}")
        del previous_status[removed]

    results = []
    safe = danger = warnings = 0

    for info in grouped.values():

        path = info["path"]
        expected_hashes = info["hashes"]

        if len(expected_hashes) > 1:
            state = "CONFLICT"
            expected_hash = "CONFLICT"

        else:

            expected_hash = next(iter(expected_hashes))

            if not os.path.exists(path):
                state = "MISSING"

            elif not os.path.isfile(path):
                state = "UNAVAILABLE"

            else:
                try:
                    actual = calculate_sha256(path)
                    state = "SAFE" if actual == expected_hash else "MODIFIED"
                except OSError:
                    state = "UNAVAILABLE"

        record_status_change(path, state)

        if state == "SAFE":
            safe += 1
        elif state in ("MODIFIED", "MISSING", "CONFLICT"):
            danger += 1
        else:
            warnings += 1

        results.append({
            "path": path,
            "state": state,
            "expected": expected_hash,
            "checked": last_scan_time
        })

    return {
        "database_ok": True, "error": None, "files": results,
        "safe": safe, "danger": danger, "warnings": warnings,
        "registered": len(results)
    }


# ============================================================
# 10. BOX DRAWING (flowing border + glitter)
# ============================================================

def flow_char(char, index, frame):
    return paint(char, fg(FLOW[(index + frame) % len(FLOW)]))


def sparkle(rng):
    return paint(
        rng.choice(SPARK_CHARS),
        fg(rng.choice(SPARK_COLOURS))
    )


def border_line(left, fill, right, inner, frame, rng):

    parts = [flow_char(left, 0, frame)]

    for i in range(inner):
        parts.append(flow_char(fill, i + 1, frame))

    parts.append(flow_char(right, inner + 1, frame))

    return BG + "".join(parts) + RESET


def box_row(content, inner, row_index, frame):

    return (
        BG
        + flow_char("│", row_index, frame)
        + pad(content, inner)
        + flow_char("│", row_index + 3, frame)
        + RESET
    )


def glitter_content(inner, rng):

    return "".join(
        sparkle(rng) if rng.random() < 0.04 else " "
        for _ in range(inner)
    )


STATE_WORDS = {
    "SAFE": "safe ✓", "MODIFIED": "changed", "MISSING": "missing",
    "CONFLICT": "conflict", "UNAVAILABLE": "can't read"
}


# ============================================================
# 11. BUILD ONE DASHBOARD FRAME
# ============================================================

def build_frame(result, frame, seconds_left):

    columns = shutil.get_terminal_size((110, 30)).columns
    inner = max(76, min(columns - 2, 118))

    rng = random.Random(frame * 7919 + 13)   # sparkles twinkle every frame
    lines = []

    def add(content=""):
        lines.append(box_row(content, inner, len(lines), frame))

    def glitter():
        add("")   # just breathing room

    def divider(left="├", right="┤"):
        lines.append(border_line(left, "─", right, inner, frame, rng))

    def thin():
        add(" " + paint("─" * (inner - 2), VIOLET))

    # ---------- header ----------
    divider("╭", "╮")

    dot = "●" if frame % 4 < 2 else "○"
    left = " " + paint("✦ file integrity hq ✦", BOLD, PINK)
    right = paint(f"{dot} live", BOLD, GREEN) + " "
    gap = max(1, inner - visible_length(left) - visible_length(right))
    add(left + " " * gap + right)

    add(" " + paint(
        "sha-256 · hmac-sha256 · watching your files so you don't have to", GREY))

    glitter()
    divider()

    # ---------- timestamps ----------
    clock = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")

    add(
        " " + paint("right now    ", GREY) + paint(clock, BOLD, GREEN)
        + "      " + paint("vibing for  ", GREY) + paint(uptime(), WHITE)
    )

    add(
        " " + paint("last scan   ", GREY) + paint(last_scan_time, BOLD, CYAN)
        + "      " + paint("scan  ", GREY)
        + paint(f"#{scan_number:04}", BOLD, WHITE)
        + "      " + paint("every  ", GREY) + paint("2.0 s", BOLD, CYAN)
    )

    progress = min(1.0, max(0.0, 1 - seconds_left / SCAN_INTERVAL))
    filled = int(progress * 30)
    bar = "▰" * filled + "▱" * (30 - filled)

    add(
        " " + paint("next scan   ", GREY) + paint(bar, PINK)
        + " " + paint(f"{seconds_left:0.1f}s", WHITE)
    )

    glitter()
    divider()

    # ---------- metrics ----------
    add(
        " " + paint("safe ♡  ", GREEN) + paint(result["safe"], BOLD, GREEN)
        + "      " + paint("sus  ", RED) + paint(result["danger"], BOLD, RED)
        + "      " + paint("hmm  ", ORANGE)
        + paint(result["warnings"], BOLD, ORANGE)
        + "      " + paint("tracked  ", GREY)
        + paint(result["registered"], WHITE)
    )

    if not result["database_ok"]:
        banner = paint("✖ database failed verification, not it", BOLD, RED)
    elif result["registered"] == 0:
        banner = paint("no files tracked yet, add some in hash.py", ORANGE)
    elif result["danger"] == 0 and result["warnings"] == 0:
        banner = paint("✓ all files safe, no cap", BOLD, GREEN)
    else:
        banner = paint("⚠ something's sus, check below", BOLD, RED)

    add(" " + banner)

    glitter()
    divider()

    # ---------- file table ----------
    status_w, base_w, time_w = 12, 14, 10
    path_w = inner - (status_w + base_w + time_w) - 5

    add(
        " " + pad(paint("✿ live file check", BOLD, WHITE), inner - 2)
    )

    add(
        " " + paint(
            f"{'file':<{path_w}} {'status':<{status_w}} "
            f"{'baseline':<{base_w}} {'checked':<{time_w}}",
            BOLD, CYAN
        )
    )
    thin()

    if not result["database_ok"]:

        add(" " + paint("lockdown: file checks paused", BOLD, RED))
        add(" " + paint(
            "can't trust results until the database verifies.",
            RED))

    elif not result["files"]:

        add(" " + paint("nothing here yet.", GREY))

    else:

        for item in result["files"][:MAX_FILE_ROWS]:

            state = item["state"]

            if state == "SAFE":
                state_colour = GREEN
            elif state in ("MODIFIED", "MISSING", "CONFLICT"):
                state_colour = RED
            else:
                state_colour = ORANGE

            baseline = item["expected"]
            if len(baseline) > base_w:
                baseline = baseline[:base_w - 3] + "..."

            add(
                " "
                + pad(shorten(item["path"], path_w), path_w) + " "
                + pad(paint(STATE_WORDS.get(state, state), BOLD, state_colour), status_w) + " "
                + pad(paint(baseline, GREY), base_w) + " "
                + paint(item["checked"], WHITE)
            )

        extra = len(result["files"]) - MAX_FILE_ROWS

        if extra > 0:
            add(" " + paint(f"+ {extra} more files", GREY))

    glitter()
    divider()

    # ---------- security panel ----------
    add(" " + paint("☾ security", BOLD, CYAN))

    auth = (
        paint("verified ✓", BOLD, GREEN)
        if result["database_ok"]
        else paint("failed", BOLD, RED)
    )

    add("   database auth   : " + auth)
    add("   hashing         : " + paint("SHA-256", WHITE))
    add("   signing         : " + paint("HMAC-SHA256", WHITE))
    add("   scan speed      : " + paint("every 2 seconds", WHITE))

    if not result["database_ok"]:
        add("   error           : " + paint(result["error"], RED))

    glitter()
    divider()

    # ---------- event history (newest first, with timestamps) ----------
    add(" " + paint("♡ recent events", BOLD, PINK))
    thin()

    if not event_history:

        add(" " + paint("all quiet for now.", GREY))

    else:

        for event in reversed(event_history):

            if "CRITICAL" in event or "ERROR" in event:
                colour_code = RED
            elif "WARNING" in event:
                colour_code = ORANGE
            else:
                colour_code = GREEN

            add(
                " " + paint("● ", colour_code)
                + paint(event[:inner - 5], WHITE)
            )

    glitter()
    divider()

    add(
        " " + paint("live ", BOLD, GREEN) + paint("· ", GREY)
        + paint("scanning every 2s ", CYAN) + paint("· ", GREY)
        + paint("ctrl+c to bounce", ORANGE)
    )

    divider("╰", "╯")

    return lines


def render(lines):

    output = "\033[H" + "".join(line + "\033[K\n" for line in lines) + "\033[J"

    sys.stdout.write(output)
    sys.stdout.flush()


# ============================================================
# 12. MAIN LOOP
# ============================================================

def start_monitor():

    try:
        key = load_secret_key()
    except (OSError, ValueError) as error:
        print(f"\nSECURITY ERROR: {error}")
        return

    load_recent_events()
    log_event("INFO", "LIVE MONITOR STARTED")

    sys.stdout.write("\033[?1049h\033[?25l\033[2J")   # own screen, hide cursor
    sys.stdout.flush()

    frame = 0
    result = None
    next_scan = 0.0

    try:

        while True:

            now = time.monotonic()

            # Scan on a fixed 2.0 s schedule (no drift).
            if result is None or now >= next_scan:

                first_scan = result is None

                result = scan_files(key)

                next_scan = (
                    now + SCAN_INTERVAL if first_scan
                    else next_scan + SCAN_INTERVAL
                )

                if next_scan <= now:
                    next_scan = now + SCAN_INTERVAL

            seconds_left = max(0.0, next_scan - time.monotonic())

            render(build_frame(result, frame, seconds_left))

            frame += 1
            time.sleep(FRAME_DELAY)

    except KeyboardInterrupt:
        pass

    finally:
        sys.stdout.write("\033[?25h\033[?1049l")      # restore terminal
        sys.stdout.flush()

    log_event("INFO", "LIVE MONITOR STOPPED")

    print(paint("monitor stopped, stay safe ✦", BOLD, PINK))
    print("Event history saved in security_log.txt")


if __name__ == "__main__":
    start_monitor()