# CISA news bot

Posts security news to the CISA @ Penn State Abington Discord using webhooks.
No bot account, no extra server permissions, Python standard library only.

| Channel | Sources |
|---|---|
| #hacktuality | The Hacker News, BleepingComputer, Krebs on Security, Dark Reading |
| #cve-alerts | CISA Known Exploited Vulnerabilities (KEV) catalog |
| #breaches-and-incidents | DataBreaches.net, The Record |
| #ctf-announcements | CTFtime upcoming events |

Edit `feeds.json` to add or remove sources (any RSS/Atom feed works).

## Setup

1. **Create a webhook per channel** in Discord: channel → Edit Channel → Integrations →
   Webhooks → New Webhook → Copy Webhook URL. Treat these URLs like passwords: anyone
   who has one can post in that channel.
2. **Push this folder to a GitHub repo** (private is fine).
3. **Add the URLs as repo secrets** (Settings → Secrets and variables → Actions):
   `WEBHOOK_HACKTUALITY`, `WEBHOOK_CVE_ALERTS`, `WEBHOOK_BREACHES`, `WEBHOOK_CTF`.
4. **Enable Actions** and click *Run workflow* once. After that it runs every hour.

The first run posts the 2 newest items per source and marks the rest as seen, so
the channels don't get flooded. Each run posts at most 4 new items per source and
never anything older than 14 days. A channel without a webhook secret is skipped.

## Local testing

```
python3 news_bot.py --dry-run
```

prints what would be posted without touching Discord or `state.json`.
