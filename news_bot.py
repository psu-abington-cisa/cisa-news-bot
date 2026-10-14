#!/usr/bin/env python3
"""CISA @ Penn State Abington news bot.

Posts scheduled digests of security news to Discord channels via webhooks.
Each channel in feeds.json has a schedule (e.g. daily at 08:15, or weekly on
Monday at 09:00, in the configured timezone) and a count. When a channel's
digest is due, the bot sends ONE message with that many new items, mixed
across its sources. Runs are cheap when nothing is due, so the workflow can
check often and still post each digest exactly once, even if GitHub's
scheduler runs late or skips runs.

Standard library only. Webhook URLs come from environment variables (never
commit them). Without a webhook set, a channel runs in dry-run mode and just
prints what it would post.

Usage:
  python3 news_bot.py              # post any digests that are due
  python3 news_bot.py --dry-run    # print only, never post, don't save state
  python3 news_bot.py --force      # ignore schedules (testing)
  NEWS_BOT_NOW=2026-10-15T08:20 python3 news_bot.py --dry-run   # pretend it's this local time
"""

import html
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from zoneinfo import ZoneInfo

HERE = Path(__file__).resolve().parent
CONFIG_PATH = HERE / "feeds.json"
STATE_PATH = HERE / "state.json"
USER_AGENT = "CISA-PSU-Abington-NewsBot/1.0 (+https://cisa.cybernet.rocks)"
MAX_ITEMS_CONSIDERED = 100  # only the newest N items of each feed are ever posted
MAX_SEEN_PER_FEED = 500     # must stay above MAX_ITEMS_CONSIDERED
WEEKDAYS = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
WEBHOOK_RE = re.compile(r"^https://(?:(?:canary|ptb)\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]+$")


def describe_bad_webhook(value):
    """Explain why a webhook value is unusable without revealing its token."""
    hints = [f"length {len(value)}"]
    if not value.startswith("https://"):
        hints.append("does not start with https://")
    elif "/api/webhooks/" not in value:
        hints.append("is a URL but not a Discord webhook URL")
    else:
        hints.append("has extra characters or a malformed ID/token")
    if any(c.isspace() for c in value):
        hints.append("contains whitespace")
    return ", ".join(hints)


def fetch(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def clean_text(raw, limit=300):
    text = re.sub(r"<[^>]+>", " ", raw or "")
    text = html.unescape(text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > limit:
        text = text[: limit - 1].rsplit(" ", 1)[0] + "…"
    return text


def parse_date(value):
    if not value:
        return None
    try:
        dt = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def parse_rss(data):
    """Return items newest-first from an RSS 2.0 or Atom document.

    Items without a date keep the feed's own order (e.g. CTFtime lists the
    soonest upcoming events first)."""
    root = ET.fromstring(data)
    items = []
    for node in root.iter():
        tag = node.tag.rsplit("}", 1)[-1]
        if tag not in ("item", "entry"):
            continue
        fields = {}
        for child in node:
            ctag = child.tag.rsplit("}", 1)[-1]
            if ctag == "link" and child.get("href"):
                fields.setdefault("link", child.get("href"))
            elif child.text:
                fields.setdefault(ctag, child.text.strip())
        link = fields.get("link", "")
        uid = fields.get("guid") or fields.get("id") or link
        if not uid:
            continue
        items.append({
            "id": uid,
            "title": clean_text(fields.get("title", "(untitled)"), 250),
            "url": link,
            "summary": clean_text(fields.get("description") or fields.get("summary") or ""),
            "date": parse_date(fields.get("pubDate") or fields.get("published") or fields.get("updated")),
        })
    items.sort(key=lambda i: i["date"] or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    return items


def parse_cisa_kev(data):
    vulns = json.loads(data)["vulnerabilities"]
    vulns.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)
    items = []
    for v in vulns:
        cve = v["cveID"]
        ransomware = v.get("knownRansomwareCampaignUse", "Unknown")
        summary = clean_text(v.get("shortDescription", ""), 280)
        summary += f"\n**Vendor/Product:** {v.get('vendorProject')} {v.get('product')}"
        summary += f"\n**Known ransomware use:** {ransomware}"
        items.append({
            "id": cve,
            "title": f"{cve}: {v.get('vulnerabilityName', '')}"[:250],
            "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
            "summary": summary,
            "date": parse_date(v.get("dateAdded")),
        })
    return items


PARSERS = {"rss": parse_rss, "cisa_kev": parse_cisa_kev}


def post_webhook(webhook_url, payload):
    body = json.dumps(payload).encode()
    for attempt in range(3):
        req = urllib.request.Request(
            webhook_url, data=body, method="POST",
            headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
        )
        try:
            with urllib.request.urlopen(req, timeout=30):
                return True
        except urllib.error.HTTPError as err:
            if err.code == 429:
                retry = json.loads(err.read() or b"{}").get("retry_after", 2)
                time.sleep(float(retry) + 0.5)
                continue
            print(f"  ! webhook error {err.code}: {err.read()[:200]!r}", file=sys.stderr)
            return False
    return False


def build_embed(item, feed_name, color):
    embed = {
        "title": item["title"],
        "url": item["url"] or None,
        "description": item["summary"] or None,
        "color": int(color, 16),
        "footer": {"text": feed_name},
    }
    if item["date"]:
        embed["timestamp"] = item["date"].astimezone(timezone.utc).isoformat()
    return {k: v for k, v in embed.items() if v is not None}


def load_json(path, default):
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def period_due(schedule, now_local, last_period):
    """Return the period key (e.g. '2026-10-15' or '2026-W42') if a digest is due, else None.

    Daily: due once the day's time has passed. Weekly: due once the weekday's
    time has passed, and still due later that week if every run that day was
    missed, but never twice in the same week."""
    hour, minute = map(int, schedule["time"].split(":"))
    if schedule["every"] == "day":
        if (now_local.hour, now_local.minute) < (hour, minute):
            return None
        key = now_local.date().isoformat()
    elif schedule["every"] == "week":
        target = WEEKDAYS.index(schedule["weekday"].lower())
        today = now_local.weekday()
        if today < target or (today == target and (now_local.hour, now_local.minute) < (hour, minute)):
            return None
        year, week, _ = now_local.isocalendar()
        key = f"{year}-W{week:02d}"
    else:
        raise ValueError(f"unknown schedule: {schedule}")
    return None if key == last_period else key


def pick_items(per_feed_new, count):
    """Pick up to `count` items, round-robin across feeds so one source can't fill the digest."""
    picked, queues = [], [list(items) for _, items in per_feed_new]
    names = [name for name, _ in per_feed_new]
    while len(picked) < count and any(queues):
        for name, queue in zip(names, queues):
            if queue and len(picked) < count:
                picked.append((name, queue.pop(0)))
    return picked


def main():
    dry_run = "--dry-run" in sys.argv
    force = "--force" in sys.argv
    config = load_json(CONFIG_PATH, None)
    if config is None:
        sys.exit(f"Missing or invalid {CONFIG_PATH}")
    tz = ZoneInfo(config.get("timezone", "America/New_York"))
    now_local = (datetime.fromisoformat(os.environ["NEWS_BOT_NOW"]).replace(tzinfo=tz)
                 if os.environ.get("NEWS_BOT_NOW") else datetime.now(tz))
    state = load_json(STATE_PATH, {})
    digests = state.setdefault("_digests", {})
    failures = False

    for channel, ch in config["channels"].items():
        schedule = ch["schedule"]
        period = period_due(schedule, now_local, digests.get(channel))
        if force:
            period = period or now_local.isoformat(timespec="minutes")
        if not period:
            continue

        webhook = os.environ.get(ch["webhook_env"], "").strip().strip("'\"<>")
        if webhook and not WEBHOOK_RE.match(webhook):
            print(f"#{channel} skipped: {ch['webhook_env']} is not a valid Discord webhook URL "
                  f"({describe_bad_webhook(webhook)})", file=sys.stderr)
            failures = True
            continue
        live = bool(webhook) and not dry_run
        print(f"#{channel} digest {period} ({'live' if live else 'dry-run'})")

        max_age = timedelta(days=schedule.get("max_age_days", 3))
        fetched, per_feed_new = {}, []
        for feed in ch["feeds"]:
            key = f"{channel}|{feed['url']}"
            try:
                items = PARSERS[feed["type"]](fetch(feed["url"]))[:MAX_ITEMS_CONSIDERED]
            except Exception as err:  # one broken feed shouldn't stop the rest
                print(f"  ! {feed['name']}: {err}", file=sys.stderr)
                continue
            fetched[key] = items
            seen = set(state.get(key, []))
            fresh = [i for i in items if i["id"] not in seen
                     and (i["date"] is None or now_local - i["date"] <= max_age)]
            per_feed_new.append((feed["name"], fresh))

        picked = pick_items(per_feed_new, schedule["count"])
        if not picked:
            print("  (nothing new)")
        else:
            header = ch["header"].format(date=f"{now_local:%a %b} {now_local.day}")
            payload = {
                "username": ch["username"],
                "content": header,
                "embeds": [build_embed(item, name, ch["color"]) for name, item in picked],
                "allowed_mentions": {"parse": []},
            }
            for name, item in picked:
                print(f"  + [{name}] {item['title']}")
            if live and not post_webhook(webhook, payload):
                failures = True
                continue  # don't record the period, so the next run retries

        if live:
            posted = {item["id"] for _, item in picked}
            for feed in ch["feeds"]:
                key = f"{channel}|{feed['url']}"
                if key not in fetched:
                    continue
                if schedule.get("skip_unposted", True):
                    # News: everything we saw is done, so tomorrow's digest is only fresh news.
                    marked = [i["id"] for i in fetched[key]]
                else:
                    # CTFs: only what we posted, so later events still get their turn.
                    marked = [i["id"] for i in fetched[key] if i["id"] in posted]
                old = state.get(key, [])
                state[key] = (marked + [s for s in old if s not in marked])[:MAX_SEEN_PER_FEED]
            digests[channel] = period

    if not dry_run:
        STATE_PATH.write_text(json.dumps(state, indent=1, sort_keys=True) + "\n")
    if failures:
        sys.exit(1)  # state is saved first, so working channels don't repeat posts


if __name__ == "__main__":
    main()
