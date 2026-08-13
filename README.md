# Sentinel Mail

**Email Security & OSINT Intelligence Platform**

SentinelMail is a terminal-based defensive security research tool for authorized email investigations and self-auditing. It analyzes an email address using legitimate public sources and produces structured findings, confidence levels, and a transparent risk score.

```bash
sentinelmail lookup user@example.com
```

## Overview

SentinelMail was built to make email-security investigation practical from a local terminal without requiring a database, web dashboard, or paid infrastructure.

The project uses a modular provider architecture so each intelligence source can be queried independently and its result can be clearly distinguished from unavailable or unverified information.

### What SentinelMail can investigate

- Email and domain validation
- DNS and mail-security configuration
- MX, SPF, DMARC, NS, A/AAAA, and CAA records
- Mail-provider information
- Domain registration data through RDAP
- Certificate Transparency records through crt.sh
- Disposable email-domain detection
- Public Gravatar information
- Public GitHub commit metadata associated with an exact email address
- Optional breach metadata through Have I Been Pwned
- Transparent 0–100 risk scoring
- Confidence-rated findings
- JSON report output

## Example

```text
SentinelMail investigating user@example.com

dns          done
rdap         done
crtsh        done
reputation   done
gravatar     done
github       done
hibp         skipped

Investigation Summary
---------------------
Email: user@example.com
Domain: example.com

Domain Security
---------------
SPF: present
DMARC: present
MX: present

Public Exposure
---------------
GitHub commits: no exact public matches found

Risk Score
----------
0/100 - Very Low
```

Results depend on the email address and the availability of information from the configured providers.

## Installation

### Requirements

- Python 3.9+
- Git
- Internet connection

Clone the repository:

```bash
git clone https://github.com/NotSoAzam/sentinelmail.git
cd sentinelmail
```

Install SentinelMail:

```bash
pip install -e .
```

Verify the installation:

```bash
sentinelmail --help
```

## Usage

### Basic lookup

```bash
sentinelmail lookup user@example.com
```

### JSON output

```bash
sentinelmail lookup user@example.com --json
```

### Save a report

```bash
sentinelmail lookup user@example.com --output report.json
```

### View provider information

```bash
sentinelmail providers
```

## Data Sources

| Provider | Purpose | Authentication |
|---|---|---|
| DNS | MX, SPF, DMARC, NS, A/AAAA, CAA and mail infrastructure | None |
| RDAP | Domain registration information | None |
| crt.sh | Certificate Transparency and subdomain discovery | None |
| Reputation | Disposable/temporary email detection | None |
| Gravatar | Public Gravatar profile detection | None |
| GitHub | Public commit metadata associated with an exact email | Optional token |
| Have I Been Pwned | Breach metadata | Optional API key |

The core SentinelMail workflow is free and does not require paid infrastructure.

## Optional Configuration

### GitHub Token

GitHub's public API can be queried without authentication, but an authenticated token provides higher API limits.

Windows PowerShell:

```powershell
$env:GITHUB_TOKEN="your_token_here"
```

Windows Command Prompt:

```cmd
set GITHUB_TOKEN=your_token_here
```

Linux/macOS:

```bash
export GITHUB_TOKEN="your_token_here"
```

Never hard-code tokens in the source code or commit them to GitHub.

### Have I Been Pwned

SentinelMail can optionally query Have I Been Pwned for breach metadata.

Configure the API key as an environment variable:

Windows PowerShell:

```powershell
$env:HIBP_API_KEY="your_api_key_here"
```

Windows Command Prompt:

```cmd
set HIBP_API_KEY=your_api_key_here
```

Linux/macOS:

```bash
export HIBP_API_KEY="your_api_key_here"
```

The breach provider reports breach metadata rather than passwords or stolen credentials.

## Risk Scoring

SentinelMail uses a transparent risk-scoring model.

| Score | Classification |
|---:|---|
| 0–20 | Very Low |
| 21–40 | Low |
| 41–60 | Moderate |
| 61–80 | High |
| 81–100 | Critical |

Potential risk signals include:

- Confirmed breach exposure
- Disposable email-domain detection
- Missing SPF configuration
- Missing DMARC configuration
- Public developer metadata exposure

The project is designed to show the evidence behind a score instead of producing an unexplained security rating.

## Confidence Levels

Findings are classified according to the strength of the available evidence.

### VERIFIED

The result was directly confirmed by the relevant provider.

### HIGH

A strong and specific match was identified.

### MEDIUM

The evidence is plausible but not conclusive.

### LOW

A weak signal was detected.

### UNVERIFIED

The provider could not confirm the result.

An unverified result is not treated as proof that an exposure exists or does not exist.

## Architecture

```text
                         Email Address
                              |
                              v
                    +-------------------+
                    | Investigation     |
                    | Engine            |
                    +---------+---------+
                              |
          +-------------------+-------------------+
          |          |         |        |         |
          v          v         v        v         v
        DNS        RDAP      crt.sh   GitHub   Reputation
          |          |         |        |         |
          +----------+---------+--------+---------+
                              |
                              v
                    +-------------------+
                    | Findings / Evidence|
                    +---------+---------+
                              |
                              v
                    +-------------------+
                    | Risk Engine        |
                    +---------+---------+
                              |
                    +---------+---------+
                    |                   |
                    v                   v
               Terminal             JSON Report
```

Each provider is isolated from the core investigation engine. This makes SentinelMail easier to test, maintain, and extend.

## Project Structure

```text
sentinelmail/
├── sentinelmail/
│   ├── cli.py
│   ├── engine.py
│   ├── models.py
│   ├── risk.py
│   ├── validation.py
│   └── providers/
│       ├── base.py
│       ├── dns_provider.py
│       ├── rdap_provider.py
│       ├── crtsh_provider.py
│       ├── reputation_provider.py
│       ├── gravatar_provider.py
│       ├── github_provider.py
│       └── hibp_provider.py
│
├── tests/
│   └── test_validation.py
│
├── requirements.txt
├── setup.py
├── .gitignore
└── README.md
```

## Testing

Run the test suite with:

```bash
pytest
```

Run SentinelMail in editable development mode:

```bash
pip install -e .
```

Then:

```bash
sentinelmail lookup user@example.com
```

## Design Principles

SentinelMail follows several principles:

1. **Evidence over assumptions**  
   Results should come from identifiable sources.

2. **Transparent uncertainty**  
   A failed or unavailable provider should not be presented as a clean result.

3. **Modular architecture**  
   Providers can be added or replaced independently.

4. **Defensive security**  
   The project focuses on security auditing and publicly available intelligence.

5. **Local-first operation**  
   The core application runs from the user's machine without requiring a hosted backend.

## Why SentinelMail Does Not Search Stolen Credential Dumps

SentinelMail does not directly access stolen credential databases, underground marketplaces, private dumps, or password collections.

A request to "search every leaked database" can involve unauthorized access to stolen data. SentinelMail instead uses legitimate breach-notification services, such as Have I Been Pwned when configured, to determine whether an email address appears in known breaches and what categories of information were exposed.

This keeps the project useful for defensive security research without retrieving or distributing stolen credentials.

## Limitations

SentinelMail is not an Internet-wide account discovery engine.

A missing result does not prove that an account, profile, breach, or exposure does not exist.

Important limitations include:

- Public information may not be indexed.
- Information may have been removed from public sources.
- GitHub API searches are subject to rate limits.
- Certificate Transparency results depend on publicly logged certificates.
- Gravatar results only represent publicly available profiles.
- Breach checks require the appropriate HIBP API access.
- Some providers may temporarily rate-limit or block automated requests.
- Provider outages can result in `UNVERIFIED` findings.
- The tool does not bypass authentication or access private accounts.

## Responsible Use

SentinelMail is intended for:

- Personal security audits
- Authorized security assessments
- Defensive cybersecurity research
- OSINT education
- Email-domain security analysis
- Cybersecurity portfolio demonstrations

Only investigate email addresses that you own or have explicit authorization to investigate.

Users are responsible for complying with applicable laws, regulations, provider terms of service, and organizational policies.

## Security

Do not commit secrets to this repository.

Never place the following directly in source code:

```text
GITHUB_TOKEN
HIBP_API_KEY
API keys
access tokens
passwords
private credentials
```

Use environment variables instead.

Before pushing the project to GitHub, verify:

```bash
git status
```

and make sure local reports, credentials, environment files, and other sensitive data are excluded by `.gitignore`.

## Roadmap

Potential future improvements:

- Additional legitimate OSINT providers
- Concurrent provider execution
- Better provider error handling
- More comprehensive automated tests
- HTML report generation
- SQLite investigation history
- Domain investigation mode
- Configurable risk-scoring policies
- CI/CD integration
- Docker support
- Security-focused structured logging
- Additional report formats
- Improved terminal presentation

## License

This project is licensed under the MIT License.

See the [LICENSE](LICENSE) file for the full license text.

## Author

**NotSoAzam**

GitHub: https://github.com/NotSoAzam

## Project Status

SentinelMail is an actively developing cybersecurity research project focused on practical email-security analysis, OSINT methodology, provider integration, and transparent risk assessment.

---

## Development Note

This project was developed with the assistance of AI tools for code generation, debugging, documentation, and development support. The implementation was reviewed, tested, and adapted as part of the development process.


**SentinelMail**

Evidence-driven email security intelligence for authorized investigations and self-auditing.

