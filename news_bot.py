#!/usr/bin/env python3
"""CISA @ Penn State Abington news bot.

Polls security news feeds and posts new items to Discord channels via webhooks.
Standard library only. Configure feeds in feeds.json; webhook URLs come from
environment variables (never commit them). Without a webhook set, a channel
runs in dry-run mode and just prints what it would post.

Usage:
  python3 news_bot.py            # post new items
  python3 news_bot.py --dry-run  # print only, never post, don't save state
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
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONFIG_PATH = HERE / "feeds.json"
STATE_PATH = HERE / "state.json"
USER_AGENT = "CISA-PSU-Abington-NewsBot/1.0 (+https://cisa.cybernet.rocks)"
MAX_ITEMS_CONSIDERED = 100  # only the newest N items of each feed are ever posted
MAX_SEEN_PER_FEED = 500     # must stay above MAX_ITEMS_CONSIDERED
MAX_AGE_DAYS = 14           # never post items older than this


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
    """Return items newest-first from an RSS 2.0 or Atom document."""
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


def main():
    dry_run = "--dry-run" in sys.argv
    config = load_json(CONFIG_PATH, None)
    if config is None:
        sys.exit(f"Missing or invalid {CONFIG_PATH}")
    state = load_json(STATE_PATH, {})
    max_posts = config.get("max_posts_per_feed_per_run", 4)
    first_run_posts = config.get("first_run_posts_per_feed", 2)

    for channel, ch in config["channels"].items():
        webhook = os.environ.get(ch["webhook_env"], "").strip()
        live = bool(webhook) and not dry_run
        print(f"#{channel} ({'live' if live else 'dry-run'})")
        for feed in ch["feeds"]:
            key = f"{channel}|{feed['url']}"
            try:
                items = PARSERS[feed["type"]](fetch(feed["url"]))[:MAX_ITEMS_CONSIDERED]
            except Exception as err:  # one broken feed shouldn't stop the rest
                print(f"  ! {feed['name']}: {err}", file=sys.stderr)
                continue
            cutoff = datetime.now(timezone.utc).timestamp() - MAX_AGE_DAYS * 86400
            items = [i for i in items if i["date"] is None or i["date"].timestamp() >= cutoff]

            first_run = key not in state
            seen = set(state.get(key, []))
            new = [i for i in items if i["id"] not in seen]
            to_post = new[: first_run_posts if first_run else max_posts]

            # Post oldest first so the channel reads chronologically.
            posted_ids = []
            for item in reversed(to_post):
                payload = {
                    "username": ch["username"],
                    "embeds": [build_embed(item, feed["name"], ch["color"])],
                    "allowed_mentions": {"parse": []},
                }
                if live:
                    if not post_webhook(webhook, payload):
                        continue
                    time.sleep(1.2)
                print(f"  + [{feed['name']}] {item['title']}")
                posted_ids.append(item["id"])

            if live:
                # On first run, mark the whole backlog as seen so we don't flood later.
                if first_run:
                    marked = [i["id"] for i in items]
                else:
                    # Items beyond the per-run cap stay unseen and go out next run.
                    unposted_new = {i["id"] for i in new} - set(posted_ids)
                    marked = [i["id"] for i in items if i["id"] not in unposted_new]
                state[key] = (marked + [s for s in state.get(key, []) if s not in marked])[:MAX_SEEN_PER_FEED]

    if not dry_run:
        STATE_PATH.write_text(json.dumps(state, indent=1, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
