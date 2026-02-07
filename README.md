# The Surveyor

**Infrastructure Mapping Engine** - Automated subdomain discovery and infrastructure analysis with selectable intensity levels.

---

## Overview

The Surveyor combines passive and active reconnaissance to map a target's external attack surface:

1. **Passive Discovery** - Certificate Transparency logs via crt.sh
2. **Active Brute-Force** - DNS enumeration with selectable intensity
3. **CNAME Resolution** - Traces DNS paths to identify providers
4. **IP Clustering** - Groups subdomains by infrastructure
5. **Outlier Detection** - Identifies potential Shadow IT

---

## Installation

```bash
cd the_surveyor
python3 -m venv venv
source venv/bin/activate
pip install requests dnspython tabulate colorama
```

---

## Usage

### Interactive Mode
```bash
python3 the_surveyor.py
```

### Command Line - Intensity Levels
```bash
# Level 1: Fast (1,000 subdomains)
python3 the_surveyor.py --domain example.com --level 1

# Level 2: Deep (20,000 subdomains) - Recommended
python3 the_surveyor.py --domain example.com --level 2

# Level 3: Insane (110,000 subdomains)
python3 the_surveyor.py --domain example.com --level 3 --threads 100

# Custom wordlist
python3 the_surveyor.py --domain example.com --wordlist custom.txt
```

### File Input
```bash
python3 the_surveyor.py --file subdomains.txt
python3 the_surveyor.py --json scout_report.json
```

---

## Intensity Levels

| Level | Wordlist Size | Use Case | Default Threads |
|-------|---------------|----------|-----------------|
| 1 (Fast) | 1,000 | Quick checks | 20 |
| 2 (Deep) | 20,000 | Standard recon | 30 |
| 3 (Insane) | 110,000 | Full coverage | 50 |

Wordlists are downloaded from remote sources into memory - no local storage required.

---

## Recon Pipeline

```
PHASE 1: Passive Reconnaissance
  - Query crt.sh for Certificate Transparency data
  - Extract subdomains from SSL/TLS certificates

PHASE 2: Active Brute-Force
  - Download selected wordlist (Level 1-3)
  - High-speed DNS resolution
  - Real-time progress: "Brute-forcing: 15,400 / 110,000 [14%]"

PHASE 3: Merge Results
  - Combine passive and active discoveries
  - Remove duplicates

PHASE 4: Infrastructure Mapping
  - Resolve CNAME chains
  - Fingerprint HTTP headers (Server, X-Powered-By)
  - Cluster by IP address
  - Detect providers (AWS, Cloudflare, etc.)
  - Flag outliers (IPs not behind CDN/WAF)
```

---

## Outlier Detection

IPs flagged as OUTLIER meet these criteria:
1. Host fewer than 3 subdomains
2. NOT behind a known CDN/WAF

Outliers often indicate development servers, Shadow IT, or WAF bypass opportunities.

---

## Output

### Console
```
+---------------+------------+-------+---------+------------+---------+
| IP Address    | Provider   | Count | Ports   | Server     | Risk    |
+===============+============+=======+=========+============+=========+
| 104.18.27.120 | Cloudflare | 15    | 80, 443 | cloudflare | Normal  |
| 192.168.1.50  | Unknown    | 1     | 80      | Apache     | OUTLIER |
+---------------+------------+-------+---------+------------+---------+
```

### JSON (surveyor_map.json)
Complete infrastructure data exported for further analysis.

---

## License

MIT License
