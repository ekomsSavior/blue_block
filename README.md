# blue_block
list, scale, block

-  Detecting suspicious signup activity from logs
-  Converting threats into actionable IP + ASN blocklists
-  Deploying rules directly to Akamai Edge + Bot Manager
---

## Setup

Clone and prepare the repo:

```bash
git clone https://github.com/ekomsSavior/blue_block.git
cd blue_block
```

## Upload Your CIAM Signups Log

Save your signups data as a CSV named:

```bash
signups.csv
```

### Required Columns:

| Field        | Description                                  |
| ------------ | -------------------------------------------- |
| `ip`         | Source IP of the signup                      |
| `email`      | Email address used                           |
| `timestamp`  | ISO format (e.g. 2025-07-24T13:55:00)        |
| `user_agent` | Full user-agent string (optional but useful) |

> You **must** include this file in the same folder before running `shield.py`.
> Use CIAM export, login audit logs, or database dump — anything works as long as the columns match.

---


## Phase 1 – CIAM Log to IP Blocklist

**Run** `shield.py`:

```bash
python3 shield.py
```

Reads `signups.csv`
Flags:

* **Disposable emails**

  * Known services (Mailinator, Sharklasers, TempMail, etc)
  * Heuristics (numeric junk + suspicious TLDs like `.xyz`)

* **Suspicious user-agents**

  * Command-line tools (curl, wget, httpclient, python-requests)
  * Privacy tools (Tor, Onion)
  * Headless browsers and bots (Selenium, Puppeteer, Playwright, PhantomJS, HeadlessChrome)
  * Missing user-agent string (empty)

* **Signup velocity**

  * 3+ signups from the same IP in under 60 seconds

 Outputs → `akamai_blocklist.txt`

> Detected IPs are auto-scored and blocked once their total score reaches a threshold of 7 or more.

---

##  Phase 2 – Build IP Set for Akamai

```bash
chmod +x akamai_uploader.sh
./akamai_uploader.sh
```

✔ Takes `akamai_blocklist.txt`
✔ Converts it into JSON format for Akamai
✔ Outputs → `akamai_edge_ipset.json`

---

##  Phase 3 – Akamai WAF Rule (IP-Based)

```json
{
  "rules": [
    {
      "name": "Block_Kraawn_IPs",
      "criteria": [
        {
          "type": "ip",
          "ipList": "KraawnShieldAutoBlock"
        }
      ],
      "action": "deny",
      "enabled": true
    }
  ]
}
```

 Upload via:

```bash
akamai edgeworkers deploy --policy akamai_edge_rule.json
```

Or through Akamai Control Center → Security Configs

---

##  Phase 4 – ASN Firewall Rule (Optional)

### asn\_blocklist.txt

```
AS16509 # Amazon AWS  
AS14061 # DigitalOcean  
AS15169 # Google Cloud  
AS24940 # Hetzner  
AS54113 # Fastly  
```

### JSON Rule Example

```json
{
  "rules": [
    {
      "name": "Block_Hosting_ASNs",
      "criteria": [
        {
          "type": "asn",
          "asnList": [16509, 14061, 15169, 24940, 54113]
        }
      ],
      "action": "deny",
      "enabled": true
    }
  ]
}
```

---

##  CLI Integration (Akamai)

```bash
akamai property-manager update-ip-list \
  --name KraawnShieldAutoBlock \
  --input akamai_edge_ipset.json
```

---

##  Summary

| Feature                    | Status  |
| -------------------------- | ------  |
| Disposable Email Detection | yes     |
| Headless Agent Flags       | yes     |
| Signup Velocity Score      | yes     |
| Akamai JSON Generator      | yes     |
| CLI + UI Deploy Ready      | yes     |
| ASN Block Support          | yes     |
