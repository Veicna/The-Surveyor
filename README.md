# The Surveyor

A **High-Intensity Hybrid Reconnaissance Engine** combining passive intelligence with aggressive active DNS enumeration for comprehensive subdomain discovery and infrastructure mapping.

## ⚠️ CRITICAL LEGAL DISCLAIMER

**READ THIS CAREFULLY - THIS TOOL PERFORMS AGGRESSIVE ACTIVE SCANNING**

### What This Tool Does

**Passive Intelligence Collection:**
- Certificate Transparency log queries (crt.sh)
- No direct target contact for initial discovery

**⚠️ AGGRESSIVE ACTIVE SCANNING:**
- **High-volume DNS brute-force attacks** (up to 110,000 queries)
- **Multi-threaded concurrent DNS resolution** (up to 100+ threads)
- **CNAME chain resolution** (multiple DNS queries per subdomain)
- **HTTP fingerprinting** (web requests to discovered hosts)

### Legal Requirements

✅ **ONLY use this tool when you have:**
- **Explicit written authorization** from the target organization
- **Confirmed scope** that includes DNS enumeration
- **Legal permission** for aggressive scanning activities
- **Authorization** for the specific intensity level you plan to use

❌ **NEVER use this tool for:**
- Unauthorized DNS enumeration of any organization
- Testing without explicit written permission
- "Curiosity scanning" or "helpful security checks"
- Any target where you lack explicit authorization

### Why This Is Serious

**This tool generates significant network activity:**

1. **DNS Server Load:**
   - Level 3 sends 110,000+ DNS queries to target nameservers
   - Can trigger rate limiting and blocking
   - May be classified as a denial-of-service attempt

2. **Detection & Logging:**
   - DNS queries are logged by nameservers
   - Activity will appear in SIEM/monitoring systems
   - Can trigger security alerts and incident response
   - Your IP address will be recorded in server logs

3. **Legal Consequences:**
   - Unauthorized DNS enumeration may violate computer fraud laws
   - Can be prosecuted as unauthorized access or reconnaissance
   - May violate terms of service and acceptable use policies
   - Could result in civil lawsuits and criminal charges

### Liability

The author assumes **ZERO responsibility** for:
- Unauthorized use of this tool
- Legal consequences including criminal prosecution
- Network disruption or service degradation
- Blacklisting of IP addresses
- Violations of applicable laws or regulations
- Damage to professional reputation

**BY USING THIS TOOL, YOU ACKNOWLEDGE:**
1. You understand the aggressive nature of this tool
2. You accept full legal responsibility for your actions
3. You have explicit authorization for all target systems
4. You will only use intensity levels appropriate for your authorization

**If you do not have proper written authorization, STOP NOW.**

---

## Overview

The Surveyor is an infrastructure mapping engine designed for authorized security assessments where aggressive enumeration is explicitly permitted. It combines passive Certificate Transparency analysis with active DNS brute-forcing to create comprehensive subdomain inventories.

**Common Use Cases (With Authorization):**
- Red team engagements with broad scanning authorization
- Internal infrastructure audits of owned domains
- Asset discovery for large organizations (authorized)
- Penetration testing with DNS enumeration in scope

---

## Technical Capabilities

### Phase 1: Passive Discovery
- Queries Certificate Transparency logs via crt.sh
- Extracts subdomains from historical SSL/TLS certificates
- No direct target contact during this phase

### Phase 2: Active DNS Brute-Force
- Downloads wordlists from public repositories (in-memory)
- Performs high-speed concurrent DNS resolution
- Three intensity levels: 1,000 / 20,000 / 110,000 queries
- Real-time progress tracking
- Configurable thread count (20-100+ threads)

### Phase 3: Result Consolidation
- Merges passive and active discoveries
- Deduplicates findings
- Validates subdomain existence

### Phase 4: Infrastructure Analysis
- **CNAME Resolution:** Traces DNS chains to identify hosting providers
- **IP Clustering:** Groups subdomains by shared infrastructure
- **HTTP Fingerprinting:** Identifies web server types (Server, X-Powered-By headers)
- **Provider Detection:** Recognizes AWS, Azure, Cloudflare, Akamai, etc.
- **Outlier Analysis:** Flags potential Shadow IT or WAF bypass opportunities

---

## Installation

Requires **Python 3.7+** and virtual environment recommended.

### 1. Clone Repository

```bash
git clone https://github.com/Veicna/The-Surveyor.git
cd The-Surveyor
```

### 2. Virtual Environment Setup

**Linux/macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

**Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

**Required packages:**
- `dnspython` - DNS resolution
- `requests` - HTTP operations
- `colorama` - Terminal output
- `tabulate` - Result formatting

---

## Usage

### ⚠️ Pre-Scan Authorization Checklist

Before running ANY scan:
- [ ] I have explicit written authorization
- [ ] Target domain is within authorized scope
- [ ] I have permission for DNS enumeration
- [ ] I understand the intensity level I'm using
- [ ] I have documented my authorization

### Interactive Mode

Launch without arguments for guided menu:

```bash
python3 the_surveyor.py
```

You will be prompted to:
1. Select scan type (domain, file, JSON input)
2. Choose intensity level
3. Configure thread count

### Command-Line Mode

#### Intensity Levels

**Level 1 (Fast) - 1,000 subdomains:**
```bash
python3 the_surveyor.py --domain example.com --level 1
```
- Suitable for: Quick reconnaissance
- Default threads: 20
- Approximate duration: 1-3 minutes

**Level 2 (Deep) - 20,000 subdomains:**
```bash
python3 the_surveyor.py --domain example.com --level 2
```
- Suitable for: Standard enumeration
- Default threads: 30
- Approximate duration: 5-15 minutes

**Level 3 (Insane) - 110,000 subdomains:**
```bash
python3 the_surveyor.py --domain example.com --level 3 --threads 100
```
- Suitable for: Comprehensive mapping (high authorization only)
- Default threads: 50 (increase to 100 for faster scans)
- Approximate duration: 15-45 minutes
- **⚠️ WARNING:** Extremely aggressive, requires explicit authorization

#### Custom Wordlist

```bash
python3 the_surveyor.py --domain example.com --wordlist custom_subdomains.txt
```

#### Input from Files

**From text file (one subdomain per line):**
```bash
python3 the_surveyor.py --file discovered_subdomains.txt
```

**From The Scout JSON output:**
```bash
python3 the_surveyor.py --json scout_report_example.com.json
```

---

## Intensity Level Comparison

| Level | Wordlist Size | Threads (Default) | Duration | Use Case |
|-------|---------------|-------------------|----------|----------|
| **1 - Fast** | 1,000 | 20 | 1-3 min | Quick initial recon |
| **2 - Deep** | 20,000 | 30 | 5-15 min | Standard enumeration |
| **3 - Insane** | 110,000 | 50-100 | 15-45 min | Comprehensive mapping |

**Wordlist Sources:**
- Level 1: rbsec/dnscan common subdomains
- Level 2: SecLists top 20,000
- Level 3: hunt3r top 110,000

All wordlists are downloaded directly into memory - no local storage required.

---

## Understanding the Reconnaissance Pipeline

### Phase 1: Passive Collection (No Target Impact)

```
[*] Phase 1: Passive Discovery
[*] Querying crt.sh for certificates...
[+] Found 47 subdomains in CT logs
```

**What happens:** The tool queries public Certificate Transparency databases. Target is not contacted.

### Phase 2: Active Brute-Force (High Target Impact)

```
[*] Phase 2: Active DNS Brute-Force
[*] Downloading wordlist...
[+] Downloaded 110,000 words
[*] Brute-forcing: 15,400 / 110,000 [14%] | Found: 23
```

**What happens:** 
- DNS A record queries sent to target nameservers
- Queries may trigger rate limiting
- Activity is logged by DNS infrastructure
- Can trigger security alerts

**⚠️ This is where legal authorization matters most.**

### Phase 3: Merge & Deduplicate

```
[*] Phase 3: Merge Results
[+] Total unique subdomains: 68
```

Combines passive and active findings, removes duplicates.

### Phase 4: Infrastructure Mapping

```
[*] Phase 4: Infrastructure Analysis
[*] Resolving CNAME chains...
[*] Fingerprinting servers...
[*] Clustering by IP...
[*] Detecting outliers...
```

**Activities:**
- Additional DNS queries for CNAME resolution
- HTTP HEAD/GET requests for server fingerprinting
- These generate additional logs on target systems

---

## Output & Analysis

### Console Output

```
╔════════════════════════════════════════════════════════════╗
║                INFRASTRUCTURE MAP                          ║
╚════════════════════════════════════════════════════════════╝

+----------------+---------------+-------+---------+-------------+---------+
| IP Address     | Provider      | Count | Ports   | Server      | Risk    |
+================+===============+=======+=========+=============+=========+
| 104.18.27.120  | Cloudflare    | 15    | 80, 443 | cloudflare  | Normal  |
| 151.101.1.195  | Fastly        | 8     | 80, 443 | varnish     | Normal  |
| 192.0.78.24    | Unknown       | 1     | 80      | nginx       | OUTLIER |
+----------------+---------------+-------+---------+-------------+---------+

OUTLIER ANALYSIS:
  1 IP(s) flagged as potential Shadow IT or WAF bypass
```

### JSON Export (surveyor_map.json)

Complete infrastructure data exported in structured JSON format:

```json
{
  "scan_meta": {
    "target": "example.com",
    "timestamp": "2025-02-07T12:34:56",
    "total_subdomains": 68,
    "intensity_level": 2
  },
  "infrastructure": {
    "104.18.27.120": {
      "provider": "Cloudflare",
      "subdomains": ["www.example.com", "api.example.com"],
      "server": "cloudflare",
      "risk_level": "Normal"
    }
  }
}
```

### Understanding Outliers

**An IP is flagged as OUTLIER when:**
1. Hosts fewer than 3 subdomains (isolated)
2. NOT behind known CDN/WAF (Cloudflare, Akamai, etc.)

**Why outliers matter:**
- Development/staging servers often missed by security teams
- Shadow IT services not under corporate governance
- Potential WAF bypass opportunities
- Forgotten infrastructure with outdated security

**Example Outliers:**
- `dev.example.com` → 192.168.1.50 (internal IP exposed)
- `old-api.example.com` → 45.33.11.78 (legacy infrastructure)

---

## Ethical Use Guidelines

### Required Authorization Documentation

Before scanning, obtain and document:

1. **Written Authorization Letter** including:
   - Explicit permission for DNS enumeration
   - Approved intensity level
   - Authorized date/time window
   - Authorized source IP addresses
   - Emergency contact information

2. **Scope Definition:**
   - List of in-scope domains
   - List of explicitly out-of-scope domains
   - Rate limiting requirements
   - Blackout windows (maintenance periods)

3. **Incident Response Plan:**
   - Contact person if scanning causes issues
   - Procedure for emergency stop
   - Escalation path for problems

### Best Practices

✅ **DO:**
- Start with Level 1 to test authorization and impact
- Coordinate with network operations teams
- Respect rate limits and adjust thread count
- Monitor for blocking and adjust accordingly
- Document all findings responsibly
- Report issues through proper channels

❌ **DON'T:**
- Jump straight to Level 3 without testing
- Scan during business-critical hours without approval
- Ignore rate limiting or blocking
- Share findings publicly without authorization
- Exceed authorized scope "to be thorough"
- Claim scanning was "accidental"

### Red Flags That Indicate You Should Stop

🚫 **Stop immediately if:**
- You receive abuse complaints
- Your IP gets blocked
- Security teams contact you unexpectedly
- You realize you lack proper authorization
- Scanning causes service degradation
- You discover you're out of scope

---

## Technical Details

### DNS Resolution Strategy

```python
resolver = dns.resolver.Resolver()
resolver.timeout = 3  # 3 second timeout per query
resolver.lifetime = 3  # Total query lifetime
```

**Thread Safety:**
- Uses `ThreadPoolExecutor` for concurrency
- Thread-safe counter with `threading.Lock`
- Real-time progress updates

### Provider Detection Logic

**CNAME Pattern Matching:**
- Checks CNAME records against 14+ known patterns
- Identifies AWS, Azure, Cloudflare, Akamai, Fastly, etc.

**HTTP Fingerprinting:**
- Analyzes `Server` and `X-Powered-By` headers
- Identifies web server technology stack

**CDN/WAF Detection:**
- Maintains list of known CDN/WAF providers
- Flags IPs that bypass edge infrastructure

---

## Troubleshooting

### Common Issues

**"Rate limited by DNS server"**
- Reduce thread count: `--threads 10`
- Use Level 1 instead of Level 3
- Add delays between queries (requires code modification)

**"Connection refused / timeout"**
- Target may be blocking your IP
- Firewall may be filtering DNS queries
- Check if you're within authorized time window

**"Permission denied"**
- Requires root/admin for raw sockets (not used by this tool)
- Check file permissions on wordlist files

**"No results found"**
- Try different intensity levels
- Verify domain is spelled correctly
- Check if target domain actually exists

---

## Limitations & Caveats

- **DNS caching:** Results may include recently removed subdomains
- **Wildcard DNS:** Some domains respond to any subdomain query
- **Rate limiting:** Aggressive scanning may trigger blocks
- **False negatives:** Not all subdomains use common naming patterns
- **Provider changes:** Infrastructure can migrate between scans
- **Passive data lag:** CT logs may not include brand-new certificates

---

## Integration with Other Tools

### Workflow: Scout → Surveyor

**Step 1:** Run The Scout (passive OSINT)
```bash
python3 the_scout.py example.com
# Generates: scout_report_example.com.json
```

**Step 2:** Feed output to The Surveyor
```bash
python3 the_surveyor.py --json scout_report_example.com.json
# Validates and expands subdomain list
```

### Export for Further Analysis

The JSON output can be imported into:
- Vulnerability scanners (Nessus, Burp Suite)
- Visualization tools (Maltego, Spiderfoot)
- Custom analysis scripts
- Reporting frameworks

---

## Contributing

Contributions welcome, but must maintain tool's ethical focus:

1. Fork repository
2. Create feature branch
3. Test changes thoroughly
4. Submit pull request with clear description

**Contribution guidelines:**
- No features that enable easier unauthorized use
- All features must respect rate limiting
- Documentation must emphasize legal requirements
- Code must include safety checks where appropriate

---

## License

MIT License - Use at your own risk and responsibility.

**License does not grant permission to:**
- Scan systems without authorization
- Violate computer fraud and abuse laws
- Ignore terms of service or acceptable use policies

---

## Support & Contact

- **Issues:** [GitHub Issues](https://github.com/Veicna/The-Surveyor/issues)
- **Security Concerns:** Report responsibly via private channels

---

## Acknowledgments

**Wordlist Sources:**
- [rbsec/dnscan](https://github.com/rbsec/dnscan) - Fast subdomain enumeration
- [danielmiessler/SecLists](https://github.com/danielmiessler/SecLists) - Deep discovery lists
- [n00py/hunt3r](https://github.com/n00py/hunt3r) - Comprehensive wordlist

**Certificate Transparency:**
- [crt.sh](https://crt.sh) - Free CT log search service

---

## Critical Final Warning

**This tool is designed for aggressive enumeration that WILL be detected.**

Unlike purely passive tools, The Surveyor:
- Sends thousands to hundreds of thousands of DNS queries
- Generates significant network traffic
- Appears in logs and monitoring systems
- Can trigger security alerts and incident response
- May cause service degradation if misconfigured

**Legal prosecution for unauthorized scanning is real and happens regularly.**

Examples of laws that may apply:
- Computer Fraud and Abuse Act (CFAA) - United States
- Computer Misuse Act - United Kingdom
- Convention on Cybercrime - European Union
- Local computer crime statutes in your jurisdiction

**DO NOT assume scanning is legal just because:**
- The tool is publicly available
- The target has weak security
- You had "good intentions"
- You work in cybersecurity
- You found the information "by accident"

**Get authorization. Stay legal. Protect yourself.** 🛡️

---

## Authorization Template

Save this template and have it signed before scanning:

```
AUTHORIZATION FOR DNS ENUMERATION

I, [Authorizing Party Name], in my capacity as [Title] for [Organization],
hereby authorize [Your Name] to perform DNS enumeration activities against
the following domain(s):

IN-SCOPE DOMAINS:
- example.com
- [add domains here]

AUTHORIZED ACTIVITIES:
- Passive Certificate Transparency queries
- Active DNS brute-force enumeration (up to Level [1/2/3])
- CNAME resolution and infrastructure mapping
- HTTP server fingerprinting

AUTHORIZATION PERIOD:
From: [Date/Time]
To: [Date/Time]

SOURCE IP ADDRESSES:
[Your IP addresses]

EMERGENCY CONTACT:
[Name, Phone, Email]

Signature: _______________ Date: _______________
```

**Keep this documentation with your scan results.**
