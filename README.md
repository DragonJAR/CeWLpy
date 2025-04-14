# CeWLPy v1.0.5 Custom Word List Generator (Python Implementation)

CeWLPy is a Python tool that spiders a website to generate useful wordlists for security assessments and penetration testing. It is based on the original [CeWL](https://github.com/digininja/CeWL) Ruby script by Robin Wood but refactored for improved structure, maintainability, and Pythonic practices.

## Key Features

- **Web Spidering:** Crawls websites up to a specified depth.
- **Wordlist Generation:** Extracts unique words from HTML/text content.
  - Optional lowercasing, removal of accents/special characters (and optionally numbers).
  - Configurable minimum and maximum word length.
- **Word Groups:** Generates consecutive groups of words (group size configurable).
- **Email Address Extraction**.
- **Metadata Extraction (requires `exiftool`):** Extracts metadata from downloaded files (PDF, Office documents, etc.).
- **Crawling Control:**
  - Follow external links (`--offsite`).
  - Support for or ignore `robots.txt`.
  - Filtering of irrelevant file extensions.
  - Exclusion of specific URL paths.
  - Configurable concurrent workers (threads), timeout, and delay.
- **Advanced HTTP Options:**
  - Custom User-Agent string.
  - HTTP Authentication (Basic/Digest).
  - HTTP/HTTPS Proxy support (optional authentication).
  - Custom HTTP Headers.
  - Ignore SSL certificate errors (`--insecure`).
- **Flexible Output:**
  - Results displayed on the console (stderr).
  - Results saved to output files.

## Installation

### Prerequisites

- **Python:** Python 3.6 or higher is required.

### Steps

1. **Install Core Dependencies:**

```bash
pip install requests beautifulsoup4
```

2. **Install Optional Dependencies (Recommended):**

- **For potentially better HTML parsing performance:**

```bash
pip install lxml
```

- **For HTTP Digest Authentication support:**

```bash
pip install requests_toolbelt
```

- **For Metadata Extraction:**
  - You **must** install `exiftool`. Download it from [exiftool.org](https://exiftool.org/).
  - Ensure the `exiftool` executable is in your system's PATH or specify its location using the `--exiftool-path` argument when running CeWLPy.

## Usage

```bash
python cewlpy.py [OPTIONS] <url>
```

### Main Arguments

| Argument                  | Description                                       | Default       |
|---------------------------|---------------------------------------------------|---------------|
| `url`                     | Starting URL to spider (required)                 | N/A           |
| `-d, --depth`             | Spidering depth                                   | `1`           |
| `-m, --min-word-length`   | Minimum word length                               | `5`           |
| `-x, --max-word-length`   | Maximum word length (0 = no limit)                | `0`           |
| `-w, --write`             | File to write wordlist/groups to                  | None          |
| `-e, --email`             | Extract email addresses found                     | False         |
| `--email-file`            | File to write email addresses to                  | None          |
| `-a, --meta`              | Enable metadata extraction                        | False         |
| `--meta-file`             | File to write metadata strings to                 | None          |
| `-g, --groups`            | Generate consecutive word groups of this size     | `0`           |
| `--with-numbers`          | Allow words containing numbers                    | False         |
| `-o, --offsite`           | Allow spidering outside the initial domain        | False         |
| `--ignore-robots`         | Ignore robots.txt rules                           | False         |
| `--workers`               | Number of concurrent spidering threads            | CPUs or `4`   |
| `--timeout`               | HTTP request timeout in seconds                   | `10.0`        |
| `--delay`                 | Minimum delay between requests in seconds         | `0.0`         |
| `-v, --verbose`           | Increase output verbosity (INFO level)            | False         |
| `--debug`                 | Enable detailed debug output (DEBUG level)        | False         |
| `-k, --keep-meta-files`   | Keep downloaded files during metadata extraction  | False         |

### Advanced Options

Consult the help menu for more advanced options related to authentication, proxies, URL exclusions, custom headers, exiftool path specification, etc.:

```bash
python cewlpy.py --help
```

## Examples

**Basic Crawl (Depth 2), Save Wordlist:**

```bash
python cewlpy.py http://example.com -d 2 -m 5 -w words.txt
```

**Crawl with Email Extraction, Ignore Robots.txt:**

```bash
python cewlpy.py http://test.com --ignore-robots -d 4 -m 5 --email --email-file emails.txt -v
```

**Metadata Extraction via Proxy, Specific ExifTool Path:**

```bash
python cewlpy.py https://internal.corp -a -k --meta-file users.txt \
--proxy-host 10.0.0.1 --proxy-port 8080 --exiftool-path /opt/exiftool/exiftool
```

**Insecure SSL, Digest Auth, Custom Header, Delay:**

```bash
python cewlpy.py https://secure.internal --insecure --delay 0.5 \
--auth-type digest --auth-user admin --auth-pass P@ssword -H "X-Custom: Value"
```

## Output

### Console Output (stderr)

- Progress messages, warnings, and errors.
- Wordlist/group results, sorted by frequency.
- Extracted emails or metadata if no file specified.

### File Output

- **Wordlist/Groups (-w filename):** Unique words/groups, sorted alphabetically.
- **Emails (--email-file filename):** Unique email addresses, sorted alphabetically.
- **Metadata (--meta-file filename):** Unique metadata strings extracted, sorted alphabetically.

### Metadata Extraction Notes

- Requires `exiftool`.
- Temporary downloads of files for metadata extraction.
- Automatically cleaned unless `-k` flag is used.
- Can consume significant time and disk space.

## License

License information not explicitly provided. Refer to repository LICENSE file or maintainer.

## Acknowledgements

Robin Wood for creating the original [CeWL](https://github.com/digininja/CeWL) Ruby script.

