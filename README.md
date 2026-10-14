# CISA news bot

Posts security news digests to the CISA @ Penn State Abington Discord using webhooks.
No bot account, no extra server permissions, Python standard library only.

| Channel | Sources | Digest (Eastern time) |
|---|---|---|
| #hacktuality | The Hacker News, BleepingComputer, Krebs on Security, Dark Reading | 5 newest stories, daily 8:15 AM |
| #cve-alerts | CISA Known Exploited Vulnerabilities (KEV) catalog | up to 5 new KEV entries, daily 8:15 AM |
| #breaches-and-incidents | DataBreaches.net, The Record | 5 newest stories, daily 8:15 AM |
| #ctf-announcements | CTFtime upcoming events | next 5 upcoming CTFs, Mondays 9:00 AM |

Each digest is one message with up to 5 links, mixed across that channel's sources.
If there's nothing new (KEV doesn't change every day), that day's digest is skipped.
Edit `feeds.json` to change sources, times, counts, or headers (any RSS/Atom feed works).

## Setup

1. **Create a webhook per channel** in Discord: channel → Edit Channel → Integrations →
   Webhooks → New Webhook → Copy Webhook URL. Treat these URLs like passwords: anyone
   who has one can post in that channel.
2. **Push this folder to a GitHub repo** (private is fine).
3. **Add the URLs as repo secrets** (Settings → Secrets and variables → Actions):
   `WEBHOOK_HACKTUALITY`, `WEBHOOK_CVE_ALERTS`, `WEBHOOK_BREACHES`, `WEBHOOK_CTF`.
4. **Enable Actions.** The workflow checks every 5 minutes around the digest times
   (plus an hourly fallback) and posts each digest once. GitHub often starts scheduled
   runs 5–30 minutes late, so a digest may land a bit after 8:15 / 9:00.

`state.json` records what has been posted and which digests have gone out
(`_digests`), so news never repeats and each digest is sent once per day/week.
News digests only include stories from the last 3 days that weren't in an earlier
digest. The CTF digest takes the next 5 upcoming events not posted before.
A channel without a webhook secret runs in dry-run mode.

## Local testing

```
python3 news_bot.py --dry-run                                  # what's due right now
NEWS_BOT_NOW=2026-10-19T09:05 python3 news_bot.py --dry-run    # pretend it's Monday 9:05 AM
python3 news_bot.py --dry-run --force                          # every channel, ignoring schedules
```

`--dry-run` never touches Discord or `state.json`.
