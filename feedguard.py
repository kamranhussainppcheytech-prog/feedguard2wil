"""
FeedGuard - protects a Google Shopping feed from silent truncation.
Runs inside GitHub Actions. No server, no cloud account, no card.

Modes:
  python feedguard.py check   - scheduled check
  python feedguard.py trust   - operator: the drop was intentional
  python feedguard.py keep    - operator: something is broken, hold the old feed
"""
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import requests
from lxml import etree

GNS = "http://base.google.com/ns/1.0"
ID_TAG = f"{{{GNS}}}id"

FEED_URL = os.environ.get("FEED_URL", "")
MAX_REMOVED = int(os.environ.get("MAX_REMOVED", "100"))
USER_AGENT = os.environ.get("USER_AGENT") or (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

STATE_FILE = Path("state.json")
OUTPUT_DIR = Path("public")
OUTPUT_FILE = OUTPUT_DIR / "feed.xml"


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def read_state():
    if not STATE_FILE.exists():
        return {"baseline": None, "status": "ok", "history": []}
    try:
        return json.loads(STATE_FILE.read_text())
    except (ValueError, OSError):
        return {"baseline": None, "status": "ok", "history": []}


def write_state(state):
    state["history"] = state.get("history", [])[-50:]
    STATE_FILE.write_text(json.dumps(state, indent=2))


def publish(xml_bytes):
    OUTPUT_DIR.mkdir(exist_ok=True)
    OUTPUT_FILE.write_bytes(xml_bytes)


def _site_root(url):
    parts = urlsplit(url)
    if parts.scheme and parts.netloc:
        return f"{parts.scheme}://{parts.netloc}/"
    return None


def _diagnose_block(response):
    """
    A refused request comes back with a page, and that page usually names who
    refused it. Read the evidence instead of guessing. Note: Cloudflare rewrites
    the Server header on everything it proxies, so the body is what tells a
    Cloudflare-made block apart from one made by the website behind it.
    """
    headers = {k.lower(): v for k, v in response.headers.items()}
    try:
        body = response.text[:8000]
    except Exception:
        body = ""
    low = body.lower()
    via_cloudflare = "cf-ray" in headers
    folder = "/wp-content/uploads/woo-feed/"

    if ("challenge" in headers.get("cf-mitigated", "").lower()
            or "just a moment" in low or "cf-chl" in low or "cf_chl" in low
            or "challenge-platform" in low):
        who = "Cloudflare bot challenge"
        fix = (f"In Cloudflare for this domain, check Security > Bots (Bot Fight Mode), "
               f"or add a custom rule that skips bot protection for {folder}")
    elif via_cloudflare and ("cf-error-details" in low or "cf-wrapper" in low
                             or "sorry, you have been blocked" in low
                             or "cloudflare ray id" in low):
        who = "Cloudflare firewall"
        fix = (f"Check Cloudflare Security > Events for this domain and allow {folder}")
    elif "wordfence" in low or "your access to this site has been limited" in low:
        who = "Wordfence (WordPress security plugin)"
        fix = (f"In WordPress, Wordfence > Firewall > Allowlisted URLs: allow {folder} "
               f"- Wordfence > Tools > Live Traffic shows the blocked request")
    elif "mod_security" in low or "modsecurity" in low:
        who = "ModSecurity (hosting server firewall)"
        fix = f"The developer or hosting company must allow {folder} in ModSecurity"
    else:
        who = "the website server itself"
        if via_cloudflare:
            who += " (Cloudflare passed the request through - the block is behind it)"
        fix = (f"The developer should check .htaccess, security plugins and the "
               f"hosting firewall for rules affecting {folder}")

    page = re.sub(r"<[^>]+>", " ", body)
    page = re.sub(r"\s+", " ", page).strip()[:160] or "(empty page)"
    return (f"HTTP {response.status_code} - blocked by {who}. "
            f"Page said: {page} -- FIX: {fix}")


def fetch_feed(url, attempts=3):
    """
    Some hosts block unrecognised clients. USER_AGENT can be set as a repository
    variable. A deliberate refusal (401/403/429) is not retried - repeating it
    changes nothing - it is diagnosed instead.
    """
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/xml,text/xml,*/*",
        "Accept-Language": "en-US,en;q=0.9",
    }
    root = _site_root(url)
    if root:
        headers["Referer"] = root

    last = None
    for _ in range(attempts):
        try:
            r = requests.get(url, timeout=300, headers=headers)
        except requests.RequestException as exc:
            last = exc
            continue
        if r.status_code in (401, 403, 429):
            raise RuntimeError(_diagnose_block(r))
        try:
            r.raise_for_status()
        except requests.RequestException as exc:
            last = exc
            continue
        return r.content
    raise RuntimeError(f"could not download the feed after {attempts} tries: {last}")


def _looks_truncated(xml_bytes):
    """
    A complete feed contains its closing tag somewhere near the end. A file
    that was cut off mid-write does not contain it at all. Checking presence
    within the last stretch of the file (rather than an exact end-match)
    tolerates trailing whitespace, blank lines, or a stray newline that some
    feed generators append.
    """
    tail = xml_bytes[-200:] if len(xml_bytes) > 200 else xml_bytes
    return b"</rss>" not in tail


# Matches an & that is NOT already part of a valid entity like &amp; or &#39;
BARE_AMP = re.compile(rb"&(?!(?:[a-zA-Z][a-zA-Z0-9]*|#[0-9]+|#[xX][0-9a-fA-F]+);)")


def _context_snippet(xml_bytes, error):
    """Pull the text immediately around a parse error so it's visible in logs
    instead of just a line/column number nobody can act on."""
    line_no = getattr(error, "lineno", 1) or 1
    col_no = getattr(error, "offset", 0) or 0
    lines = xml_bytes.split(b"\n")
    if 0 < line_no <= len(lines):
        line = lines[line_no - 1]
        start = max(0, col_no - 40)
        end = min(len(line), col_no + 40)
        try:
            return line[start:end].decode("utf-8", errors="replace")
        except Exception:
            return "(could not decode this section)"
    return "(could not locate the error location)"


def count_items(xml_bytes):
    """
    Strict parse. Truncated files must fail loudly - that is the whole point.
    Bare & characters are repaired, because a complete feed with messy text is
    a different problem from a feed that got cut off halfway.
    """
    if not xml_bytes:
        raise ValueError("the feed was empty")

    parser = etree.XMLParser(huge_tree=True)
    try:
        root = etree.fromstring(xml_bytes, parser=parser)
    except etree.XMLSyntaxError as first_error:
        snippet = _context_snippet(xml_bytes, first_error)
        if _looks_truncated(xml_bytes):
            raise ValueError(
                f"the feed is cut off - it does not end properly "
                f"({first_error}) near: ...{snippet}...")
        repaired = BARE_AMP.sub(b"&amp;", xml_bytes)
        if repaired == xml_bytes:
            raise ValueError(
                f"the feed is not valid XML: {first_error} near: ...{snippet}...")
        try:
            root = etree.fromstring(repaired, parser=etree.XMLParser(huge_tree=True))
        except etree.XMLSyntaxError as second_error:
            raise ValueError(
                f"the feed is not valid XML even after repair: {second_error} "
                f"near: ...{snippet}...")
        print(f"::warning::Your feed contains raw & characters near: ...{snippet}... "
              f"FeedGuard repaired them, but Google may reject the original feed. "
              f"Check your product titles and descriptions.")

    channel = root.find("channel")
    if channel is None:
        raise ValueError("no <channel> element found - this is not a valid feed")
    ids = {
        item.findtext(ID_TAG).strip()
        for item in channel.findall("item")
        if item.findtext(ID_TAG) and item.findtext(ID_TAG).strip()
    }
    if not ids:
        raise ValueError("the feed contained no products")
    return len(ids)


def repaired_bytes(xml_bytes):
    """The bytes we should publish: repaired if repair was needed and safe."""
    if _looks_truncated(xml_bytes):
        return xml_bytes
    try:
        etree.fromstring(xml_bytes, parser=etree.XMLParser(huge_tree=True))
        return xml_bytes
    except etree.XMLSyntaxError:
        return BARE_AMP.sub(b"&amp;", xml_bytes)


def emit(**outputs):
    """Hand values back to the GitHub Actions workflow."""
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a") as fh:
        for key, value in outputs.items():
            # One line only, and no characters that could break the shell
            # command the workflow builds from these values.
            clean = re.sub(r"[\r\n]+", " ", str(value))
            clean = re.sub(r'[`"$\\]', "", clean)
            fh.write(f"{key}={clean}\n")


# --------------------------------------------------------------------------

def check():
    state = read_state()

    try:
        raw = fetch_feed(FEED_URL)
        count = count_items(raw)
        raw = repaired_bytes(raw)
    except Exception as exc:
        state["last_run"] = now()
        state["last_error"] = str(exc)
        state.setdefault("history", []).append(
            {"at": now(), "count": None, "result": "download_failed"})
        write_state(state)
        print(f"::error::Could not read the feed: {exc}")
        print("The last good feed is still being served to Google.")
        emit(result="download_failed", publish="false", detail=str(exc))
        return 1

    state["last_error"] = None
    state["last_count"] = count
    state["last_run"] = now()
    baseline = state.get("baseline")

    if baseline is None:
        publish(raw)
        state.update(baseline=count, status="ok")
        state.setdefault("history", []).append(
            {"at": now(), "count": count, "result": "first_publish"})
        write_state(state)
        print(f"Baseline set: {count} products. Feed published.")
        emit(result="first_publish", publish="true", count=count)
        return 0

    removed = baseline - count

    if state.get("status") == "pending":
        state["pending_count"] = count
        state.setdefault("history", []).append(
            {"at": now(), "count": count, "result": "still_waiting"})
        write_state(state)
        print(f"Still waiting for your decision. Feed currently has {count} "
              f"products, baseline is {baseline}. Nothing published.")
        emit(result="still_waiting", publish="false", count=count)
        return 0

    if state.get("status") == "held":
        if removed <= MAX_REMOVED:
            publish(raw)
            state.update(baseline=count, status="ok")
            state.setdefault("history", []).append(
                {"at": now(), "count": count, "result": "recovered"})
            write_state(state)
            print(f"Your feed recovered ({count} products). Publishing resumed.")
            emit(result="recovered", publish="true", count=count)
            return 0
        state.setdefault("history", []).append(
            {"at": now(), "count": count, "result": "still_held"})
        write_state(state)
        print(f"Still holding. Your feed has {count} products, expected "
              f"around {baseline}.")
        emit(result="still_held", publish="false", count=count)
        return 0

    if removed <= MAX_REMOVED:
        publish(raw)
        state.update(baseline=count, status="ok")
        state.setdefault("history", []).append(
            {"at": now(), "count": count, "result": "published"})
        write_state(state)
        print(f"Published {count} products (change: {-removed:+d}).")
        emit(result="published", publish="true", count=count)
        return 0

    # Too many gone. Stop and ask.
    state.update(status="pending", pending_count=count, pending_at=now())
    state.setdefault("history", []).append(
        {"at": now(), "count": count, "result": "asked"})
    write_state(state)
    print(f"::warning::{removed} products disappeared from your feed "
          f"({baseline} -> {count}). Nothing published.")
    emit(result="asked", publish="false", count=count,
         baseline=baseline, removed=removed)
    return 0


def trust():
    state = read_state()
    if state.get("status") != "pending":
        print("Nothing is waiting for a decision.")
        emit(result="nothing_pending", publish="false")
        return 0

    raw = fetch_feed(FEED_URL)
    count = count_items(raw)
    publish(repaired_bytes(raw))
    state.update(baseline=count, status="ok")
    state.setdefault("history", []).append(
        {"at": now(), "count": count, "result": "you_approved"})
    write_state(state)
    print(f"Published {count} products. That is your new normal.")
    emit(result="you_approved", publish="true", count=count)
    return 0


def keep():
    state = read_state()
    if state.get("status") != "pending":
        print("Nothing is waiting for a decision.")
        emit(result="nothing_pending", publish="false")
        return 0

    state["status"] = "held"
    state.setdefault("history", []).append(
        {"at": now(), "count": state.get("pending_count"), "result": "you_held"})
    write_state(state)
    print(f"Keeping the last good feed ({state.get('baseline')} products). "
          f"Publishing resumes automatically once your feed recovers.")
    emit(result="you_held", publish="false")
    return 0


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "check"
    if not FEED_URL:
        print("::error::FEED_URL is not set. Add it in repository settings "
              "under Secrets and variables > Actions > Variables.")
        sys.exit(1)
    sys.exit({"check": check, "trust": trust, "keep": keep}[mode]())
