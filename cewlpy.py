# -*- coding: utf-8 -*-
"""
CeWLPy: Custom Word List Generator (Python Implementation)

CeWLPy spiders a target site to generate lists useful for security assessments:
- A word list of all unique words (lowercase, accents removed).
- A list of email addresses found.
- A list of potential usernames/author details from document metadata (requires exiftool).
- Groups of words up to a specified size.

Based on the original CeWL Ruby script by Robin Wood.

Refactored for improved structure, maintainability, and Pythonic practices.
"""

__version__ = "1.0.5"

import sys
import importlib
import argparse
import os
import re
import logging
import tempfile
import subprocess
import time
import shutil
import unicodedata
import dataclasses
from collections import deque, Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from queue import Queue, Empty
from urllib.parse import urlparse, urljoin, urldefrag, urlunparse
from urllib.robotparser import RobotFileParser
from typing import (
    Set, List, Tuple, Optional, Dict, Deque, Any, Counter as CounterType,
    NamedTuple, Generator
)

# --- Dependency Check ---

REQUIRED_DEPS = {
    'requests': 'requests',
    'bs4': 'beautifulsoup4'
}

def check_dependencies():
    """Checks for required external libraries."""
    missing_deps = []
    for imp, pkg in REQUIRED_DEPS.items():
        try:
            importlib.import_module(imp)
        except ImportError:
            missing_deps.append(pkg)

    if missing_deps:
        print("\nError: Missing required Python libraries.", file=sys.stderr)
        print(f"Please install them using pip: pip install {' '.join(missing_deps)}\n", file=sys.stderr)
        sys.exit(1)

check_dependencies()

# --- Import External Libraries ---

import requests
from requests.exceptions import RequestException
from requests.adapters import HTTPAdapter
# Conditionally import HTTPDigestAuth if needed later
try:
    from requests.auth import HTTPDigestAuth
    HAS_DIGEST_AUTH = True
except ImportError:
    HAS_DIGEST_AUTH = False
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
import urllib3 # For disabling warnings

# --- Constants ---

# Determine best HTML parser
HTML_PARSER = 'html.parser'
try:
    import lxml
    HTML_PARSER = 'lxml'
    LXML_AVAILABLE = True
except ImportError:
    LXML_AVAILABLE = False

USER_AGENT = f"Mozilla/5.0 (X11; Linux x86_64; Storebot-Google/1.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36"
DEFAULT_DEPTH = 1
DEFAULT_MIN_WORD_LENGTH = 5
DEFAULT_MAX_WORD_LENGTH = 0 # 0 means no limit
DEFAULT_TIMEOUT = 10.0
DEFAULT_WORKERS = os.cpu_count() or 4
DEFAULT_RETRIES = 3
DEFAULT_META_TIMEOUT = 30
DEFAULT_PROXY_PORT = 8080

# Sets for efficient lookups
COMMON_IGNORED_EXTENSIONS = frozenset({
    '.zip', '.gz', '.bz2', '.rar', '.tar', '.tgz', '.7z',
    '.png', '.gif', '.jpg', '.jpeg', '.bmp', '.svg', '.ico',
    '.mp3', '.wav', '.ogg', '.mp4', '.avi', '.mkv', '.mov',
    '.swf', '.flv',
    '.exe', '.dll', '.deb', '.rpm', '.dmg',
})

METADATA_EXTENSIONS = frozenset({
    '.pdf',
    '.doc', '.docx',
    '.xls', '.xlsx',
    '.ppt', '.pptx',
    '.odt', '.ods', '.odp'
})

# Content types likely containing processable text
TEXTUAL_CONTENT_TYPES = frozenset({
    'text/plain', 'text/xml', 'application/xml', 'text/css',
    'application/json', 'application/javascript', 'text/javascript',
    'application/rss+xml', 'application/atom+xml',
    'text/html',
})

# --- Logging Setup ---

logging.basicConfig(level=logging.WARNING, format='%(levelname)s: [%(threadName)s] %(message)s', stream=sys.stderr)
log = logging.getLogger(__name__)

# --- Configuration Dataclass ---

@dataclasses.dataclass(frozen=True)
class CrawlConfig:
    """Holds all configuration settings for the crawl."""
    start_url: str
    normalized_start_url: str
    base_scheme: str
    base_netloc: str
    depth: int
    offsite: bool
    exclude_patterns: Set[str]
    allowed_pattern: Optional[re.Pattern]
    timeout: float
    workers: int
    ignore_robots: bool
    delay: float
    min_word_length: int
    max_word_length: Optional[int] # None means no limit
    no_words: bool
    groups: int
    with_numbers: bool
    extract_email: bool
    extract_meta: bool
    meta_temp_dir: str
    meta_timeout: int
    exiftool_path_hint: Optional[str]
    keep_meta_files: bool
    word_output_file: Optional[str]
    email_output_file: Optional[str]
    meta_output_file: Optional[str]
    user_agent: str
    auth_type: Optional[str]
    auth_user: Optional[str]
    auth_pass: Optional[str]
    proxy_host: Optional[str]
    proxy_port: Optional[int]
    proxy_username: Optional[str]
    proxy_password: Optional[str]
    custom_headers: Dict[str, str]
    retries: int
    insecure_ssl: bool
    log_level: int

# --- Utility Functions ---

def normalize_url(url: str) -> str:
    """Ensures a URL has a scheme, defaulting to 'http://'."""
    parsed = urlparse(url)
    if not parsed.scheme:
        if url.startswith("//"):
            return "http:" + url
        # Basic check if it looks like just a domain/ip
        if '.' in url or ':' in url or url == 'localhost':
             return "http://" + url
        # Could be a relative path, handle upstream or raise error if it's the start URL
        raise ValueError(f"Cannot normalize URL without scheme or clear host: {url}")
    return url

def get_extension(url: str) -> Optional[str]:
    """Extracts the lowercased file extension from a URL's path."""
    try:
        path = urlparse(url).path
        if path and '.' in os.path.basename(path): # Check basename to avoid dots in dirs
            # Handle multi-part like .tar.gz specifically
            if path.lower().endswith('.tar.gz'):
                return '.tar.gz'
            elif path.lower().endswith('.tar.bz2'):
                 return '.tar.bz2'
            # General case
            return os.path.splitext(path)[1].lower()
    except ValueError:
        log.warning(f"Could not parse path from URL to get extension: {url}")
    return None

def clean_text(text: str, allow_numbers: bool) -> str:
    """
    Cleans text: lowercase, remove accents, filter non-alphanumeric, normalize space.
    """
    if not isinstance(text, str):
        return ""

    # 1. Lowercase
    text = text.lower()

    # 2. Remove accents (decompose and filter combining characters)
    try:
        # Handle specific cases like ñ first if normalization fails
        text = text.replace('ñ', 'n')
        nfkd_form = unicodedata.normalize('NFD', text)
        ascii_text = "".join(c for c in nfkd_form if not unicodedata.combining(c))
        text = ascii_text
    except Exception as e:
        # Log the specific error but try to continue
        log.warning(f"Accent removal failed for a text segment: {e}. Using original segment: '{text[:50]}...'")

    # 3. Filter characters (keep letters, optionally numbers, and whitespace)
    if allow_numbers:
        # Keep a-z, 0-9, and whitespace (\s)
        pattern = r'[^a-z0-9\s]+'
    else:
        # Keep only a-z and whitespace (\s)
        pattern = r'[^a-z\s]+'
    cleaned_text = re.sub(pattern, ' ', text)

    # 4. Normalize whitespace (replace multiple spaces/newlines with single space)
    cleaned_text = re.sub(r'\s+', ' ', cleaned_text).strip()

    return cleaned_text

def extract_emails(text: str) -> Set[str]:
    """Extracts potential email addresses using a common regex."""
    if not isinstance(text, str):
        return set()
    # Reasonably robust regex, avoids overly simple matches
    # Allows for new TLDs, standard characters in local/domain parts
    email_pattern = r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
    return set(re.findall(email_pattern, text))

def find_exiftool(path_hint: Optional[str]) -> Optional[str]:
    """Finds and verifies the exiftool executable."""
    cmd_to_test = None
    source_checked = ""

    if path_hint:
        source_checked = f"explicit path '{path_hint}'"
        log.debug(f"Checking for exiftool via {source_checked}")
        found_path = shutil.which(path_hint)
        if found_path:
            cmd_to_test = found_path
        else:
            log.error(f"Provided exiftool path not found or not executable: {path_hint}")
            return None
    else:
        source_checked = "'exiftool' in system PATH"
        log.debug(f"Checking for {source_checked}")
        found_path = shutil.which('exiftool')
        if found_path:
            log.debug(f"Found 'exiftool' in PATH at: {found_path}")
            cmd_to_test = found_path
        else:
            log.debug("'exiftool' not found in system PATH.")
            return None

    # Verify it runs
    try:
        log.debug(f"Testing exiftool command: {cmd_to_test}")
        result = subprocess.run(
            [cmd_to_test, '-ver'],
            capture_output=True, check=True, timeout=10, text=True
        )
        log.info(f"Exiftool ({source_checked}) confirmed operational (Version: {result.stdout.strip()}). Path: {cmd_to_test}")
        return cmd_to_test
    except FileNotFoundError:
        log.error(f"Exiftool command '{cmd_to_test}' execution failed (FileNotFound) checking {source_checked}.")
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
        log.error(f"Error encountered while testing {source_checked} ('{cmd_to_test}'): {e}")
    except Exception as e:
        log.error(f"Unexpected error testing exiftool ({source_checked}): {e}")

    return None

# --- Core Classes ---

class Fetcher:
    """Handles HTTP requests using a configured requests.Session."""
    def __init__(self, config: CrawlConfig):
        self.config = config
        self.session = self._configure_session()
        log.debug("Fetcher initialized.")

    def _configure_session(self) -> requests.Session:
        """Sets up the requests session based on CrawlConfig."""
        session = requests.Session()

        headers = {'User-Agent': self.config.user_agent}
        headers.update(self.config.custom_headers)
        # Log if User-Agent was overridden by custom headers
        if 'User-Agent' in self.config.custom_headers:
             log.info(f"Overriding default User-Agent with custom header value: {self.config.custom_headers['User-Agent']}")
        elif 'user-agent' in self.config.custom_headers: # Check case-insensitively
             log.info(f"Overriding default User-Agent with custom header value: {self.config.custom_headers['user-agent']}")
        session.headers.update(headers)
        log.debug(f"Session headers set: {session.headers}")

        # Authentication
        if self.config.auth_type:
            auth_user = self.config.auth_user
            auth_pass = self.config.auth_pass
            if self.config.auth_type == 'basic':
                session.auth = (auth_user, auth_pass)
                log.info(f"Using HTTP Basic Authentication for user '{auth_user}'.")
            elif self.config.auth_type == 'digest':
                if not HAS_DIGEST_AUTH:
                    log.critical("Digest authentication requested but requires 'requests_toolbelt'. Install it or use Basic.")
                    sys.exit(1) # Or raise an exception
                session.auth = HTTPDigestAuth(auth_user, auth_pass)
                log.info(f"Using HTTP Digest Authentication for user '{auth_user}'.")

        # Proxy
        if self.config.proxy_host:
            port = self.config.proxy_port or DEFAULT_PROXY_PORT
            proxy_host = self.config.proxy_host
            proxy_url_base = f"{proxy_host}:{port}"
            proxy_auth = ""
            if self.config.proxy_username:
                user = self.config.proxy_username
                passwd = self.config.proxy_password or ""
                proxy_auth = f"{user}:{passwd}@"
                log.info("Proxy authentication enabled.")

            # Scheme matters for proxy URL
            proxy_url = f"http://{proxy_auth}{proxy_url_base}" # Assume http proxy for now
            proxies = {"http": proxy_url, "https": proxy_url} # Apply to both http/https target URLs
            session.proxies = proxies
            log.info(f"Using proxy server at {proxy_host}:{port}")

        # SSL Verification
        session.verify = not self.config.insecure_ssl
        if self.config.insecure_ssl:
            log.warning("Disabling SSL certificate verification (--insecure)! This is INSECURE.")
            try:
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                log.debug("Suppressed InsecureRequestWarning from urllib3.")
            except AttributeError:
                log.warning("Could not disable InsecureRequestWarning (urllib3 version might differ).")

        # Retries
        retries = Retry(
            total=self.config.retries,
            backoff_factor=0.5, # Modest backoff
            status_forcelist=[429, 500, 502, 503, 504], # Retry on these statuses
            allowed_methods=frozenset(['GET']), # Only retry GET
        )
        adapter = HTTPAdapter(max_retries=retries)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        log.debug(f"Configured requests session with {self.config.retries} retries (backoff=0.5, statuses=[429, 5xx]).")

        return session

    def fetch(self, url: str) -> Optional[requests.Response]:
        """Fetches a URL, handling timeouts, redirects, and retries."""
        try:
            log.debug(f"Attempting to fetch URL: {url}")
            response = self.session.get(
                url,
                timeout=self.config.timeout if self.config.timeout > 0 else None,
                allow_redirects=True,
                stream=True # Important for potentially large downloads/checking headers first
            )
            # Check status code *before* reading full content
            response.raise_for_status()

            # Log success after status check
            final_url = response.url
            log_msg = f"Successfully fetched [{response.status_code}] {url}"
            if final_url != url:
                 log_msg += f" (final URL: {final_url})"
            log.info(log_msg)
            return response

        except RequestException as e:
            # Log specific request errors after retries have failed
            log.error(f"Failed to fetch {url} after retries: {e}")
        except Exception as e:
            # Catch unexpected errors during the request phase
            log.error(f"Unexpected error fetching {url}: {e}", exc_info=(self.config.log_level <= logging.DEBUG))
        finally:
             # Ensure the connection is closed if we streamed but didn't consume
             # However, returning the response object delegates closing to the consumer.
             # If an exception occurred *before* returning, Requests should handle cleanup.
             pass

        return None

    def close(self):
        """Closes the underlying session."""
        self.session.close()
        log.debug("Fetcher session closed.")


class UrlFilter:
    """Applies filtering rules to determine if a URL should be crawled."""
    def __init__(self, config: CrawlConfig, fetcher_session: requests.Session):
        self.config = config
        self._session_for_robots = fetcher_session # Needed to fetch robots.txt
        self.robot_parsers: Dict[str, Optional[RobotFileParser]] = {} # Cache: base_url -> parser or None
        self.robot_parsers_lock = Lock()
        log.debug("UrlFilter initialized.")

    def _get_robot_parser(self, url: str) -> Optional[RobotFileParser]:
        """Retrieves or fetches/parses robots.txt for the URL's domain."""
        if self.config.ignore_robots:
            return None

        try:
            parsed_url = urlparse(url)
            # Key should include scheme and netloc
            base_url_key = f"{parsed_url.scheme.lower()}://{parsed_url.netloc.lower()}"
            robots_url = urljoin(base_url_key, '/robots.txt')

            with self.robot_parsers_lock:
                if base_url_key in self.robot_parsers:
                    # Return cached parser (could be None if fetch failed previously)
                    return self.robot_parsers[base_url_key]

            # Not in cache, attempt fetch (outside lock to avoid holding it during I/O)
            log.info(f"Fetching and parsing robots.txt from: {robots_url}")
            rp = RobotFileParser()
            rp.set_url(robots_url)
            fetched_rp: Optional[RobotFileParser] = None # Use temporary variable

            try:
                # Use a shorter timeout for robots.txt than general requests
                fetch_timeout = max(1, self.config.timeout / 2) if self.config.timeout > 0 else 5
                # Use the *Fetcher's session* to respect proxy/auth if needed for robots.txt
                response = self._session_for_robots.get(robots_url, timeout=fetch_timeout, allow_redirects=True, stream=False)
                response.raise_for_status()
                # Use apparent encoding or fallback to utf-8, ignore errors
                response.encoding = response.apparent_encoding or 'utf-8'
                robots_content = response.text

                rp.parse(robots_content.splitlines())
                log.debug(f"Successfully parsed robots.txt for {base_url_key}")
                fetched_rp = rp # Assign only on success

            except RequestException as e:
                log.warning(f"Could not fetch robots.txt from {robots_url}: {e}. Assuming allow all for this domain.")
                # Cache None to avoid retrying fetch constantly
            except Exception as e:
                log.error(f"Error parsing robots.txt from {robots_url}: {e}. Assuming allow all.")
                # Cache None

            # Update cache under lock
            with self.robot_parsers_lock:
                self.robot_parsers[base_url_key] = fetched_rp
            return fetched_rp

        except Exception as e:
            log.error(f"Unexpected error getting/processing robot parser for {url}: {e}")
            return None # Fail safe: assume allowed if robots processing fails unexpectedly

    def is_valid_to_queue(self, link: str, current_depth: int) -> bool:
        """Checks if a discovered link should be added to the crawl queue."""
        MAX_URL_LENGTH = 2048 # Common practical limit

        # 1. Basic sanity checks
        if not link or len(link) > MAX_URL_LENGTH:
            log.debug(f"Ignoring invalid or overly long link ({len(link)} chars): {link[:100]}...")
            return False

        # 2. Parse the link
        try:
            parsed_link = urlparse(link)
        except ValueError:
            log.warning(f"Could not parse URL during filtering: {link}")
            return False

        # 3. Scheme check (only http/https for crawling)
        if parsed_link.scheme not in ('http', 'https'):
            # We handle mailto extraction elsewhere if needed, just don't queue it
            log.debug(f"Ignoring non-HTTP/S scheme link: {link}")
            return False

        # 4. Depth check
        next_depth = current_depth + 1
        if next_depth > self.config.depth:
            log.debug(f"Max depth ({self.config.depth}) reached, not queuing [Depth:{next_depth}]: {link}")
            return False

        # 5. Offsite check
        if not self.config.offsite:
            link_netloc = parsed_link.netloc.lower()
            if link_netloc != self.config.base_netloc:
                log.debug(f"Offsite link ignored (base:'{self.config.base_netloc}', link:'{link_netloc}'): {link}")
                return False

        # 6. Robots.txt check
        if not self.config.ignore_robots:
            robot_parser = self._get_robot_parser(link)
            user_agent = self.config.user_agent
            if robot_parser and not robot_parser.can_fetch(user_agent, link):
                log.info(f"Excluding link disallowed by robots.txt: {link}")
                return False
            elif robot_parser is None and base_url_key in self.robot_parsers: # Check if fetch failed
                 log.debug(f"Allowing link as robots.txt fetch/parse failed for its domain: {link}")
            # If robot_parser is None and not in cache, _get_robot_parser failed unexpectedly, default allow

        # 7. File Extension check (Common non-content + Metadata handling)
        extension = get_extension(link)
        if extension:
            is_common_ignored = extension in COMMON_IGNORED_EXTENSIONS
            # Allow metadata docs only if meta extraction is enabled
            is_meta_doc = self.config.extract_meta and extension in METADATA_EXTENSIONS

            if is_common_ignored and not is_meta_doc:
                log.debug(f"Ignoring link by common non-content extension '{extension}': {link}")
                return False

        # 8. Exclusion patterns check
        if self.config.exclude_patterns:
            path_to_check = parsed_link.path or "/"
            # Ensure path starts with / for matching consistency
            if not path_to_check.startswith('/'): path_to_check = '/' + path_to_check

            # Check path only first
            if path_to_check in self.config.exclude_patterns:
                log.info(f"Excluding link by path '{path_to_check}' matching exclusion list: {link}")
                return False
            # Check path + query if query exists
            if parsed_link.query:
                path_query_to_check = f"{path_to_check}?{parsed_link.query}"
                if path_query_to_check in self.config.exclude_patterns:
                    log.info(f"Excluding link by path+query '{path_query_to_check}' matching exclusion list: {link}")
                    return False

        # 9. Allowed pattern check
        if self.config.allowed_pattern:
            path_for_allow_check = parsed_link.path or '/'
            if not self.config.allowed_pattern.search(path_for_allow_check):
                log.info(f"Excluding link - path '{path_for_allow_check}' does not match allowed regex pattern: {link}")
                return False

        # If all checks pass:
        log.debug(f"Link passed all filters, valid to queue: {link}")
        return True


@dataclasses.dataclass
class ProcessingResult:
    """Holds the results of processing a single page/document."""
    words: List[str] = dataclasses.field(default_factory=list)
    groups: List[str] = dataclasses.field(default_factory=list)
    emails: Set[str] = dataclasses.field(default_factory=set)
    metadata: Set[str] = dataclasses.field(default_factory=set)
    new_links: Set[str] = dataclasses.field(default_factory=set)


class ContentProcessor:
    """Abstract base class for processing different content types."""
    def __init__(self, config: CrawlConfig):
        self.config = config

    def process(self, response: requests.Response) -> ProcessingResult:
        """Processes the response content and returns extracted data."""
        raise NotImplementedError

    def _extract_and_filter_words(self, text: str) -> List[str]:
        """Helper to clean text and filter words by length."""
        if not text or self.config.no_words:
            return []

        cleaned_text = clean_text(text, self.config.with_numbers)
        words = cleaned_text.split()

        # Apply length filters
        min_len = self.config.min_word_length
        # Use infinity if max_len is None (0 from arg means no limit -> None)
        max_len = self.config.max_word_length if self.config.max_word_length is not None else float('inf')

        return [word for word in words if min_len <= len(word) <= max_len]

    def _generate_groups(self, words: List[str]) -> List[str]:
        """Generates word groups of the configured size."""
        if not words or self.config.groups <= 1: # Groups require at least 2 words
            return []

        groups = []
        group_size = self.config.groups
        # Use a deque for efficient sliding window
        current_group: Deque[str] = deque(maxlen=group_size)
        for word in words:
            current_group.append(word)
            if len(current_group) == group_size:
                groups.append(' '.join(current_group))
        return groups


class HtmlProcessor(ContentProcessor):
    """Processes HTML content."""
    def process(self, response: requests.Response) -> ProcessingResult:
        result = ProcessingResult()
        log.debug(f"Processing HTML content from: {response.url}")
        try:
            # Use response.content for BeautifulSoup to handle encoding better
            soup = BeautifulSoup(response.content, HTML_PARSER)

            # 1. Extract Links (before modifying soup potentially)
            base_url = response.url # Use final URL after redirects
            result.new_links = self._extract_links(soup, base_url)

            # 2. Extract Text for Words/Emails
            # Remove common non-content elements
            tags_to_remove = ["script", "style", "noscript", "nav", "footer", "aside", "form", "header", "button", "select", "textarea", "input", "head"] # Added head
            for element in soup(tags_to_remove):
                element.decompose()

            # Get text from body (preferable) or whole doc if no body
            body = soup.body
            main_text = body.get_text(separator=' ', strip=True) if body else soup.get_text(separator=' ', strip=True)

            # Include relevant attribute text
            alt_texts = [tag.get('alt', '') for tag in soup.find_all(alt=True)]
            title_texts = [tag.get('title', '') for tag in soup.find_all(title=True)]
            # Consider meta description/keywords if they weren't in <head> and removed
            meta_texts = [tag.get('content', '') for tag in soup.find_all('meta', attrs={'name': ['description', 'keywords']})]

            full_text = ' '.join(filter(None, [main_text] + alt_texts + title_texts + meta_texts))

            # 3. Extract Emails
            if self.config.extract_email:
                result.emails = extract_emails(full_text)
                # Also check mailto links specifically
                result.emails.update(self._extract_mailto_emails(soup))
                if result.emails:
                     log.info(f"Found {len(result.emails)} email(s) in HTML of {response.url}")

            # 4. Extract Words and Groups
            if not self.config.no_words:
                filtered_words = self._extract_and_filter_words(full_text)
                if filtered_words:
                    result.words = filtered_words
                    result.groups = self._generate_groups(filtered_words)
                    log.debug(f"Extracted {len(result.words)} words (and {len(result.groups)} groups) from HTML {response.url}")

        except Exception as e:
            log.error(f"Error processing HTML content on {response.url}: {e}", exc_info=(self.config.log_level <= logging.DEBUG))

        return result

    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> Set[str]:
        """Extracts unique, absolute HTTP/HTTPS links from 'a' tags."""
        links: Set[str] = set()
        MAX_URL_LENGTH = 2048
        IGNORED_LINK_PREFIXES = ('javascript:', '#', 'tel:', 'sms:', 'data:')

        for link_tag in soup.find_all('a', href=True):
            href = link_tag['href'].strip()

            # Basic filtering of non-crawlable or problematic hrefs
            if not href or href.lower().startswith(IGNORED_LINK_PREFIXES) or href == '#':
                continue

            try:
                # Resolve relative URLs
                absolute_link = urljoin(base_url, href)
                # Remove fragment identifier (#...)
                absolute_link_no_frag, _ = urldefrag(absolute_link)
                # Parse the absolute link
                parsed_abs = urlparse(absolute_link_no_frag)

                # Check scheme and length
                if parsed_abs.scheme in ('http', 'https') and len(absolute_link_no_frag) < MAX_URL_LENGTH:
                    links.add(absolute_link_no_frag)
                elif parsed_abs.scheme not in ('http', 'https'):
                    # Handle mailto separately if needed, but don't add to crawl links
                    if parsed_abs.scheme != 'mailto':
                         log.debug(f"Ignoring non-crawlable scheme link: {absolute_link_no_frag}")
                else:
                    log.warning(f"Ignoring potentially malformed/long URL ({len(absolute_link_no_frag)} chars) from href='{href}' on page {base_url}")

            except ValueError as e:
                # Catch errors during urljoin or urlparse
                log.warning(f"Could not process href='{href}' on page {base_url}: {e}")

        log.debug(f"Extracted {len(links)} unique, absolute HTTP/S links from {base_url}")
        return links

    def _extract_mailto_emails(self, soup: BeautifulSoup) -> Set[str]:
        """Extracts emails specifically from mailto: links."""
        emails = set()
        if not self.config.extract_email:
            return emails

        for link_tag in soup.find_all('a', href=True):
            href = link_tag['href'].strip()
            if href.lower().startswith('mailto:'):
                try:
                    # Simple extraction, remove mailto: and potential params like ?subject=...
                    email_part = href[len('mailto:'):].split('?')[0]
                    if '@' in email_part and '.' in email_part: # Basic validation
                        # Double check with regex for better robustness
                        found = extract_emails(email_part)
                        emails.update(found)
                except Exception as e:
                    log.warning(f"Could not parse mailto link '{href}': {e}")
        return emails


class MetadataProcessor(ContentProcessor):
    """Processes document files to extract metadata using exiftool."""
    def __init__(self, config: CrawlConfig, exiftool_cmd: str):
        super().__init__(config)
        self.exiftool_cmd = exiftool_cmd
        log.debug(f"MetadataProcessor initialized with exiftool: {exiftool_cmd}")
        self._ensure_temp_dir()

    def _ensure_temp_dir(self):
        """Checks if the temporary directory for metadata files is valid."""
        temp_dir = self.config.meta_temp_dir
        log.debug(f"Checking metadata temporary directory: {temp_dir}")
        if not os.path.isdir(temp_dir):
            log.critical(f"Metadata temporary directory does not exist or is not a directory: {temp_dir}")
            # Use sys.exit directly here as it's a critical config issue
            sys.exit(1)
        if not os.access(temp_dir, os.W_OK | os.X_OK):
            log.critical(f"Metadata temporary directory is not writable/executable: {temp_dir}")
            sys.exit(1)

    def process(self, response: requests.Response) -> ProcessingResult:
        result = ProcessingResult()
        log.info(f"Processing document for metadata: {response.url}")
        extension = get_extension(response.url) or '.tmp'
        temp_file_path: Optional[str] = None

        try:
            # Create a temporary file to store the document content
            # Use NamedTemporaryFile for automatic handling, but delete=False to control removal
            with tempfile.NamedTemporaryFile(delete=False, dir=self.config.meta_temp_dir,
                                             suffix=extension, mode='wb') as temp_f:
                temp_file_path = temp_f.name
                bytes_written = 0
                # Stream download to handle potentially large files
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk: # filter out keep-alive new chunks
                        temp_f.write(chunk)
                        bytes_written += len(chunk)

            log.debug(f"Saved {bytes_written} bytes from {response.url} to temporary file: {temp_file_path}")

            # Only run exiftool if the file is not empty
            if bytes_written > 0:
                metadata_found = self._run_exiftool(temp_file_path)
                if metadata_found:
                    result.metadata = set(metadata_found) # Convert list to set
                    log.info(f"Found metadata in {response.url}: {result.metadata}")
            else:
                log.warning(f"Skipping exiftool processing - temporary file is empty for {response.url} (Path: {temp_file_path})")

        except IOError as e:
            log.error(f"IOError writing temporary file for {response.url}: {e}")
        except Exception as e:
            log.error(f"Error during metadata processing for {response.url}: {e}", exc_info=(self.config.log_level <= logging.DEBUG))
        finally:
            # Cleanup the temporary file unless --keep is specified
            if temp_file_path and os.path.exists(temp_file_path):
                if not self.config.keep_meta_files:
                    try:
                        os.remove(temp_file_path)
                        log.debug(f"Removed temporary file: {temp_file_path}")
                    except OSError as e:
                        log.error(f"Could not remove temporary file {temp_file_path}: {e}")
                else:
                    log.info(f"Keeping downloaded document as requested: {temp_file_path}")

        return result

    def _run_exiftool(self, filepath: str) -> List[str]:
        """Runs exiftool on the file and extracts relevant metadata fields."""
        metadata_items: Set[str] = set()
        # Fields commonly containing usernames or author info
        # -T for tab-separated, -q quiet, -s short output (value only)
        # Using specific tags is generally more reliable than broad groups
        tags_to_extract = ['-Author', '-Creator', '-Producer', '-LastModifiedBy', '-CreatorTool', '-Contributor']

        try:
            log.debug(f"Running exiftool ({self.exiftool_cmd}) on: {filepath}")
            command = [self.exiftool_cmd, '-T', '-q'] + tags_to_extract + [filepath]

            result = subprocess.run(
                command,
                capture_output=True,
                text=True,          # Decode stdout/stderr as text
                check=False,        # Don't raise exception on non-zero exit, check returncode instead
                encoding='utf-8',   # Specify encoding
                errors='ignore',    # Ignore decoding errors if exiftool outputs weird chars
                timeout=self.config.meta_timeout
            )

            if result.returncode == 0 and result.stdout:
                # Output is tab-separated values for the requested tags
                line = result.stdout.strip()
                # Split by tab and filter out empty strings or placeholder '-'
                potential_items = [item.strip() for item in line.split('\t') if item.strip() and item.strip() != '-']
                metadata_items.update(potential_items)

            elif result.returncode != 0:
                stderr_info = f" Stderr: {result.stderr.strip()}" if result.stderr else ""
                # File not found by exiftool is often code 1, don't log as error unless debug
                if result.returncode == 1 and "File not found" in result.stderr:
                     log.debug(f"Exiftool reported file not found (code 1) for {filepath}. Might be OS/path issue.")
                else:
                     log.warning(f"Exiftool exited with code {result.returncode} for {filepath}. Command: '{' '.join(command)}'.{stderr_info}")

        except FileNotFoundError:
            # This shouldn't happen if find_exiftool worked, but handle defensively
            log.error(f"Exiftool command '{self.exiftool_cmd}' not found at runtime.")
            # Potentially disable further meta attempts? For now, just log.
        except subprocess.TimeoutExpired:
            log.error(f"Exiftool timed out (>{self.config.meta_timeout}s) processing {filepath}.")
        except Exception as e:
            log.error(f"Unexpected error running exiftool on {filepath}: {e}")

        return list(metadata_items) # Return list as per original intent


class TextProcessor(ContentProcessor):
    """Processes generic text-based content (CSS, JS, XML, etc.)."""
    def process(self, response: requests.Response) -> ProcessingResult:
        result = ProcessingResult()
        content_type = response.headers.get('Content-Type', '').lower().split(';')[0].strip()
        log.debug(f"Processing '{content_type}' content from: {response.url}")

        try:
            # Decode text content, respecting apparent encoding or falling back
            # Use response.text which handles this
            text_content = response.text
            if not text_content:
                log.debug(f"Skipping empty text content from {response.url}")
                return result

            # 1. Extract Emails
            if self.config.extract_email:
                result.emails = extract_emails(text_content)
                if result.emails:
                    log.info(f"Found {len(result.emails)} email(s) in '{content_type}' content of {response.url}")

            # 2. Extract Words (no groups from generic text usually)
            if not self.config.no_words:
                result.words = self._extract_and_filter_words(text_content)
                if result.words:
                    log.debug(f"Extracted {len(result.words)} words from '{content_type}' content of {response.url}")

        except Exception as e:
            # Catch potential decoding errors or others during text processing
            log.error(f"Error processing text content type '{content_type}' on {response.url}: {e}", exc_info=(self.config.log_level <= logging.DEBUG))

        return result


class Crawler:
    """Orchestrates the web crawling process."""

    def __init__(self, config: CrawlConfig, exiftool_cmd: Optional[str]):
        self.config = config
        self.fetcher = Fetcher(config)
        self.url_filter = UrlFilter(config, self.fetcher.session) # Pass session for robots.txt

        # --- Processors ---
        self.html_processor = HtmlProcessor(config)
        self.metadata_processor = None
        if config.extract_meta and exiftool_cmd:
            self.metadata_processor = MetadataProcessor(config, exiftool_cmd)
        self.text_processor = TextProcessor(config)

        # --- Shared State (Thread-Safe) ---
        self.urls_to_visit: Queue[Tuple[str, int]] = Queue()
        self.visited_urls_lock = Lock()
        self.visited_urls: Set[str] = set() # URLs submitted for processing (incl. queue)

        self.results_lock = Lock() # Single lock for all result collections
        self.word_counts: CounterType[str] = Counter()
        self.group_counts: CounterType[str] = Counter()
        self.found_emails: Set[str] = set()
        self.found_metadata: Set[str] = set()

        # Add starting URL
        self.urls_to_visit.put((self.config.normalized_start_url, 0))
        self.visited_urls.add(self.config.normalized_start_url)

        self.running = True # Flag for graceful shutdown

        log.debug("Crawler initialized.")

    def _select_processor(self, response: requests.Response) -> Optional[ContentProcessor]:
        """Determines the appropriate content processor based on response."""
        content_type = response.headers.get('Content-Type', '').lower().split(';')[0].strip()
        extension = get_extension(response.url)

        # Priority 1: Metadata files (if enabled)
        if self.metadata_processor and extension in METADATA_EXTENSIONS:
            return self.metadata_processor

        # Priority 2: HTML content
        # Check content-type first, then extension as fallback
        if 'html' in content_type or extension in ('.html', '.htm'):
            return self.html_processor

        # Priority 3: Other likely textual content types
        if content_type in TEXTUAL_CONTENT_TYPES or 'text/' in content_type:
            return self.text_processor

        # Default: No specific processor for this type
        log.debug(f"No specific processor for content type '{content_type}', extension '{extension}' at {response.url}")
        return None

    def _worker(self):
        """The main loop for each worker thread."""
        log.debug(f"Worker '{threading.current_thread().name}' started.")
        while self.running:
            try:
                # Get next URL from queue, non-blocking with timeout
                # Timeout allows checking self.running periodically
                current_url, current_depth = self.urls_to_visit.get(block=True, timeout=0.5)
            except Empty:
                # Check if crawling should stop or if queue is just temporarily empty
                # A more robust check might involve seeing if other threads are active
                # For simplicity now, assume if queue is empty and timeout hit, maybe done
                # Check if queue is *really* empty (another thread might add)
                if self.urls_to_visit.empty():
                     log.debug(f"Worker '{threading.current_thread().name}' found queue empty, potentially finishing.")
                     # Could add logic here to wait briefly and recheck, or check active thread count
                     break # Exit loop if queue seems permanently empty
                continue # Queue was empty but might refill, loop again

            try:
                log.info(f"Processing [Depth:{current_depth}]: {current_url}")

                # Apply delay if configured
                if self.config.delay > 0:
                    time.sleep(self.config.delay)

                # Fetch the page
                response = self.fetcher.fetch(current_url)
                if not response:
                    # Fetch failed (logged in fetcher), mark task done and continue
                    self.urls_to_visit.task_done()
                    continue

                # Process content using the appropriate processor
                # Need to consume content before selecting processor reliably sometimes
                # Let processors handle consuming content (e.g., response.text, response.content)
                processor = self._select_processor(response)
                processing_result = None
                if processor:
                    try:
                        # Ensure response content is read *before* task_done if streaming
                        # Processors should handle reading response.content or response.text
                        processing_result = processor.process(response)
                    finally:
                        # Important: Close the response body to release connection,
                        # especially if using stream=True in fetcher
                        response.close()
                else:
                     # If no processor, still need to close the response
                     response.close()

                # Aggregate results (if any) under lock
                if processing_result:
                    with self.results_lock:
                        if processing_result.words:
                            self.word_counts.update(processing_result.words)
                        if processing_result.groups:
                            self.group_counts.update(processing_result.groups)
                        if processing_result.emails:
                            self.found_emails.update(processing_result.emails)
                        if processing_result.metadata:
                            self.found_metadata.update(processing_result.metadata)

                    # Queue new valid links (if any found by HTML processor)
                    if processing_result.new_links:
                        links_added_count = 0
                        for link in processing_result.new_links:
                            # Check if valid to queue (depth, offsite, robots, etc.)
                            if self.url_filter.is_valid_to_queue(link, current_depth):
                                # Check if *already visited or queued* (thread-safe)
                                with self.visited_urls_lock:
                                    if link not in self.visited_urls:
                                        self.visited_urls.add(link)
                                        self.urls_to_visit.put((link, current_depth + 1))
                                        links_added_count += 1
                                    # else: log.debug(f"Link already visited/queued, skipping: {link}")
                        if links_added_count > 0:
                            log.debug(f"Queued {links_added_count} new valid links from {current_url}")

            except Exception as e:
                # Catch unexpected errors within the worker loop for a specific URL
                log.error(f"Unexpected error processing URL {current_url}: {e}", exc_info=(self.config.log_level <= logging.DEBUG))
            finally:
                 # Ensure task_done is called even if errors occur for this URL
                 try:
                      self.urls_to_visit.task_done()
                 except ValueError:
                      # Can happen if task_done called more times than put
                      log.warning(f"task_done() called unexpectedly for {current_url}")


        log.debug(f"Worker '{threading.current_thread().name}' finished.")

    def run(self):
        """Starts and manages the thread pool for crawling."""
        log.warning(f"--- CeWLPy {__version__} Starting Crawl ---")
        log.info(f"Target: {self.config.start_url}")
        log.info(f"Settings: Depth={self.config.depth}, Workers={self.config.workers}, Timeout={self.config.timeout}s, Delay={self.config.delay}s")
        # Add more key settings logs...

        start_time = time.time()
        self.running = True

        with ThreadPoolExecutor(max_workers=self.config.workers, thread_name_prefix='CeWLPyWorker') as executor:
            # Submit initial workers
            futures = {executor.submit(self._worker) for _ in range(self.config.workers)}
            log.info(f"Started {len(futures)} worker threads.")

            try:
                # Wait for queue to be processed
                # This relies on workers exiting when queue is empty and task_done is called
                self.urls_to_visit.join() # Blocks until all items are gotten and processed
                log.info("URL queue processing complete.")

            except KeyboardInterrupt:
                log.warning("\nCtrl+C detected! Attempting graceful shutdown...")
                self.running = False # Signal workers to stop
                # Workers checking self.running should exit their loops.
                # Executor shutdown (implicit in 'with' block exit) will wait.
                # Note: Tasks currently running will complete. fetch requests might timeout.
                print("\nShutdown initiated. Waiting for active tasks... Results gathered so far will be processed.", file=sys.stderr)

            except Exception as e:
                 log.critical(f"Unexpected error during crawl execution management: {e}", exc_info=True)
                 self.running = False # Ensure workers stop on unexpected errors too

            finally:
                 # Ensure running is False if loop finishes normally too
                 self.running = False
                 # Executor shutdown happens automatically here

        end_time = time.time()
        log.warning(f"Crawling phase finished in {end_time - start_time:.2f} seconds.")
        # Use len(self.visited_urls) for a count of URLs considered (queued or processed)
        # Note: visited_urls includes the start URL and potentially URLs filtered out later
        # A more accurate "processed" count would require tracking inside the worker success path
        log.info(f"Considered approximately {len(self.visited_urls)} unique URLs.")

        # Close the fetcher session explicitly
        self.fetcher.close()


class OutputWriter:
    """Handles writing collected data to console and files."""

    def __init__(self, config: CrawlConfig):
        self.config = config

    def write_results(self,
                      word_counts: CounterType[str],
                      group_counts: CounterType[str],
                      emails: Set[str],
                      metadata: Set[str]):
        """Writes all collected results based on configuration."""
        log.warning("Processing collected data for output...")
        output_generated = False

        # --- Wordlist / Groups Output ---
        if not self.config.no_words:
            combined_items = word_counts + group_counts # Combine counters
            if combined_items:
                output_generated = True
                # Console Output (Frequency sorted)
                print("\n--- Word/Group Frequencies (Sorted by Count - Console Output) ---", file=sys.stderr)
                # Sort by count descending, then alphabetically
                sorted_items_for_console = sorted(combined_items.items(), key=lambda item: (-item[1], item[0]))
                for item, count in sorted_items_for_console:
                    # Use repr for item to show quotes clearly for multi-word groups
                    print(f"{repr(item)}: {count}")
                print("--- End Word/Group Frequencies ---", file=sys.stderr)

                # File Output (Alphabetically sorted, no counts by default)
                if self.config.word_output_file:
                    log.info(f"Preparing alphabetically sorted wordlist for file: {self.config.word_output_file}")
                    # Get unique words/groups only
                    items_only = list(combined_items.keys())
                    self._write_to_file(items_only, self.config.word_output_file, header="# Wordlist / Groups")
            else:
                log.warning("Word list generation enabled, but no words/groups meeting criteria were found.")

        # --- Email Output ---
        if self.config.extract_email:
            if emails:
                output_generated = True
                sorted_emails = sorted(list(emails))
                if self.config.email_output_file:
                    log.info(f"Writing {len(sorted_emails)} emails to file: {self.config.email_output_file}")
                    self._write_to_file(sorted_emails, self.config.email_output_file, header="# Email Addresses")
                else:
                    # Print to console if no specific file
                    print("\n--- Found Email Addresses (Console Output) ---", file=sys.stderr)
                    for email in sorted_emails: print(email)
                    print("--- End Email Addresses ---", file=sys.stderr)
            else:
                log.warning("Email extraction enabled, but no emails were found.")

        # --- Metadata Output ---
        if self.config.extract_meta:
            if metadata:
                output_generated = True
                sorted_metadata = sorted(list(metadata))
                if self.config.meta_output_file:
                     log.info(f"Writing {len(sorted_metadata)} metadata items to file: {self.config.meta_output_file}")
                     self._write_to_file(sorted_metadata, self.config.meta_output_file, header="# Metadata (Authors/Usernames etc.)")
                else:
                     # Print to console if no specific file
                     print("\n--- Found Metadata Items (Console Output) ---", file=sys.stderr)
                     for item in sorted_metadata: print(item)
                     print("--- End Metadata Items ---", file=sys.stderr)
            else:
                 # Only warn if exiftool was actually found and expected to run
                 if self.metadata_processor: # Check if processor was initialized
                     log.warning("Metadata extraction enabled, but no metadata was found in processed documents.")
                 # else: No warning if exiftool wasn't found initially

        if not output_generated:
            log.warning("No data matching the specified criteria was found or generated by the crawl.")

    def _write_to_file(self, data_items: List[str], filename: str, header: Optional[str] = None):
        """Helper to write a list of strings to a file."""
        output_target = f"file '{filename}'"
        log.info(f"Writing {len(data_items)} items to {output_target}")
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                if header:
                    f.write(header + "\n")
                for item in data_items:
                    try:
                        f.write(f"{item}\n")
                    except Exception as e:
                        # Log error for specific item but try to continue
                        log.error(f"Error writing item '{str(item)[:50]}...' to {output_target}: {e}")
        except IOError as e:
            log.critical(f"Fatal Error: Could not write to output {output_target}: {e}")
            # Exit here if file writing fails, as it's a primary function
            sys.exit(1)
        except Exception as e:
            log.critical(f"Fatal Error: Unexpected issue writing output {output_target}: {e}")
            sys.exit(1)
        log.info(f"Finished writing output to {output_target}")


# --- Argument Parsing ---

def parse_arguments() -> argparse.Namespace:
    """Parses command-line arguments using argparse."""
    parser = argparse.ArgumentParser(
        description=f"CeWLPy {__version__} - Custom Word List Generator (Python).",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=f"""Examples:
  Basic crawl, depth 2, save words to file (console shows counts):
    python cewlpy.py http://example.com -d 2 -w words.txt

  Deeper crawl, ignore robots, min length 5, include emails (file & console):
    python cewlpy.py http://test.com --ignore-robots -d 4 -m 5 --email -e --email-file emails.txt -v

  Extract metadata, keep files, use proxy, specify exiftool path:
    python cewlpy.py https://internal.corp -a -k --meta-file users.txt \\
      --proxy-host 10.0.0.1 --proxy-port 8080 --exiftool-path /opt/exiftool/exiftool

  Crawl internal site with self-signed cert, digest auth, custom header, delay:
    python cewlpy.py https://secure.internal --insecure --delay 0.5 \\
      --auth-type digest --auth-user admin --auth-pass P@ssword -H "X-Custom: Value"
"""
    )

    # Argument Groups for better organization in --help
    req_group = parser.add_argument_group('Required Argument')
    spider_group = parser.add_argument_group('Spider Control')
    wordlist_group = parser.add_argument_group('Word List Control')
    meta_group = parser.add_argument_group('Metadata Control (requires exiftool)')
    email_group = parser.add_argument_group('Email Control')
    output_group = parser.add_argument_group('Output Control')
    http_group = parser.add_argument_group('HTTP/Network Control')

    # Required
    req_group.add_argument('url', help='The starting URL to spider.')

    # Spider Control
    spider_group.add_argument('-d', '--depth', type=int, default=DEFAULT_DEPTH, metavar='<int>', help=f'Depth to spider (default: {DEFAULT_DEPTH}). 0=start page only.')
    spider_group.add_argument('-o', '--offsite', action='store_true', help='Allow spidering to other domains.')
    spider_group.add_argument('--exclude', metavar='<file>', help='File containing paths/patterns to exclude (one per line, # comments). Matches path or path?query.')
    spider_group.add_argument('--allowed', metavar='<regex>', help='Regex pattern that the URL path must match.')
    spider_group.add_argument('--timeout', type=float, default=DEFAULT_TIMEOUT, metavar='<secs>', help=f'HTTP request timeout (0=none) (default: {DEFAULT_TIMEOUT}).')
    spider_group.add_argument('--workers', type=int, default=DEFAULT_WORKERS, metavar='<int>', help=f'Number of concurrent workers (default: {DEFAULT_WORKERS}).')
    spider_group.add_argument('--ignore-robots', action='store_true', help='Ignore robots.txt rules (use with caution).')
    spider_group.add_argument('--delay', type=float, default=0.0, metavar='<secs>', help='Minimum delay between requests per worker (default: 0).')

    # Word List Control
    wordlist_group.add_argument('-m', '--min-word-length', type=int, default=DEFAULT_MIN_WORD_LENGTH, metavar='<int>', help=f'Minimum word length (default: {DEFAULT_MIN_WORD_LENGTH}).')
    wordlist_group.add_argument('-x', '--max-word-length', type=int, default=DEFAULT_MAX_WORD_LENGTH, metavar='<int>', help=f'Maximum word length (0=no limit) (default: {DEFAULT_MAX_WORD_LENGTH}).')
    wordlist_group.add_argument('-n', '--no-words', action='store_true', help="Disable wordlist/group generation and output.")
    wordlist_group.add_argument('-g', '--groups', type=int, default=0, metavar='<int>', help='Generate groups of N consecutive words (0=disabled) (default: 0).')
    wordlist_group.add_argument('--with-numbers', action='store_true', help='Allow words containing numbers (0-9). Default is letters only.')
    # Removed -c/--count as it's default console behavior now

    # Metadata Control
    meta_group.add_argument('-a', '--meta', action='store_true', help='Enable metadata analysis (requires "exiftool").')
    meta_group.add_argument('--meta-file', metavar='<file>', help='Output file specifically for metadata results.')
    meta_group.add_argument('--meta-temp-dir', default=tempfile.gettempdir(), metavar='<dir>', help='Directory for temporary document files (default: system temp). Needs write access.')
    meta_group.add_argument('--meta-timeout', type=int, default=DEFAULT_META_TIMEOUT, metavar='<secs>', help=f'Timeout for running exiftool per file (default: {DEFAULT_META_TIMEOUT}).')
    meta_group.add_argument('--exiftool-path', metavar='<path>', help='Optional path to the exiftool executable.')
    meta_group.add_argument('-k', '--keep', action='store_true', help='Keep downloaded document files in temp dir.')

    # Email Control
    email_group.add_argument('-e', '--email', action='store_true', help='Enable extraction of email addresses.')
    email_group.add_argument('--email-file', metavar='<file>', help='Output file specifically for found email addresses.')

    # Output Control
    output_group.add_argument('-w', '--write', metavar='<file>', help='Write main wordlist/groups (alphabetical, no counts) to file. Console always shows counts.')
    output_group.add_argument('-v', '--verbose', action='store_const', const=logging.INFO, dest='log_level', help='Increase verbosity (INFO level).')
    output_group.add_argument('--debug', action='store_const', const=logging.DEBUG, dest='log_level', help='Enable highly detailed debug output (DEBUG level).')

    # HTTP/Network Control
    http_group.add_argument('-u', '--ua', metavar='<agent>', default=USER_AGENT, help=f'Custom User-Agent string (default: "{USER_AGENT}").')
    http_group.add_argument('--auth-type', choices=['basic', 'digest'], help='HTTP Authentication type.')
    http_group.add_argument('--auth-user', metavar='<user>', help='Username for HTTP Auth.')
    http_group.add_argument('--auth-pass', metavar='<pass>', help='Password for HTTP Auth.')
    http_group.add_argument('--proxy-host', metavar='<host>', help='Proxy server hostname or IP.')
    http_group.add_argument('--proxy-port', type=int, metavar='<port>', help=f'Proxy server port (default: {DEFAULT_PROXY_PORT} if --proxy-host set).')
    http_group.add_argument('--proxy-username', metavar='<user>', help='Username for proxy auth.')
    http_group.add_argument('--proxy-password', metavar='<pass>', help='Password for proxy auth.')
    http_group.add_argument('-H', '--header', action='append', metavar='"Name: Value"', help="Add custom HTTP header (use multiple times).")
    http_group.add_argument('--retries', type=int, default=DEFAULT_RETRIES, metavar='<int>', help=f'Number of retries for failed HTTP requests (default: {DEFAULT_RETRIES}).')
    http_group.add_argument('--insecure', action='store_true', help='Disable SSL/TLS certificate verification (INSECURE!).')

    # Version
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')

    # Set default log level
    parser.set_defaults(log_level=logging.WARNING)

    args = parser.parse_args()

    # --- Argument Validation ---
    if args.min_word_length < 1: parser.error("--min-word-length must be at least 1.")
    if args.max_word_length != 0 and args.max_word_length < args.min_word_length: parser.error("--max-word-length cannot be less than --min-word-length.")
    if args.depth < 0: parser.error("--depth cannot be negative.")
    if args.groups < 0: parser.error("--groups cannot be negative.")
    if args.workers < 1: parser.error("--workers must be at least 1.")
    if args.timeout < 0: parser.error("--timeout cannot be negative (0 = none).")
    if args.delay < 0: parser.error("--delay cannot be negative.")
    if args.retries < 0: parser.error("--retries cannot be negative.")
    if args.meta_timeout <= 0: parser.error("--meta-timeout must be positive.")

    # Auth validation
    if args.auth_type and not (args.auth_user and args.auth_pass): parser.error("--auth-type requires both --auth-user and --auth-pass.")
    if (args.auth_user or args.auth_pass) and not args.auth_type: parser.error("--auth-user/--auth-pass requires --auth-type.")

    # Proxy validation
    if (args.proxy_username or args.proxy_password) and not args.proxy_host: parser.error("Proxy authentication requires --proxy-host.")
    if args.proxy_host and not args.proxy_port: args.proxy_port = DEFAULT_PROXY_PORT

    # Header validation
    if args.header:
        for h in args.header:
            if ':' not in h or h.strip().startswith(':') or h.strip().endswith(':'):
                parser.error(f"Invalid header format: '{h}'. Expected 'HeaderName: HeaderValue'.")

    # Check digest auth dependency if selected
    if args.auth_type == 'digest' and not HAS_DIGEST_AUTH:
         parser.error("Digest authentication requires 'requests_toolbelt'. Please install it (`pip install requests_toolbelt`).")

    return args

def create_config_from_args(args: argparse.Namespace) -> CrawlConfig:
    """Creates the CrawlConfig object from parsed arguments."""

    # Normalize Start URL early
    try:
        norm_url = normalize_url(args.url)
        parsed_start = urlparse(norm_url)
        if not parsed_start.scheme or not parsed_start.netloc:
            raise ValueError("Normalized URL still lacks scheme or netloc.")
    except ValueError as e:
        log.critical(f"Invalid start URL: {args.url} - Error: {e}")
        sys.exit(1)

    # Load Exclusions
    exclusions: Set[str] = set()
    if args.exclude:
        log.info(f"Loading exclusion list from: {args.exclude}")
        try:
            if not os.path.isfile(args.exclude):
                log.error(f"Exclusion file not found: {args.exclude}")
                # Continue without exclusions, but log error
            else:
                with open(args.exclude, 'r', encoding='utf-8') as f:
                    for line in f:
                        path = line.strip()
                        if path and not path.startswith('#'):
                            # Store path relative to root (ensure leading /)
                            if not path.startswith('/'): path = '/' + path
                            exclusions.add(path)
                            log.debug(f"Added exclusion: {path}")
                log.info(f"Loaded {len(exclusions)} exclusion pattern(s).")
        except IOError as e:
            log.error(f"Could not read exclusion file {args.exclude}: {e}")
        except Exception as e:
            log.error(f"Unexpected error processing exclusion file {args.exclude}: {e}")

    # Compile Allowed Regex
    allowed_pattern: Optional[re.Pattern] = None
    if args.allowed:
        log.info(f"Compiling allowed path regex pattern: {args.allowed}")
        try:
            allowed_pattern = re.compile(args.allowed)
        except re.error as e:
            log.critical(f"Invalid regex pattern for allowed paths: '{args.allowed}' - {e}")
            sys.exit(1)

    # Process Custom Headers
    custom_headers: Dict[str, str] = {}
    if args.header:
        for header_arg in args.header:
            name, value = header_arg.split(':', 1)
            custom_headers[name.strip()] = value.strip()
            log.debug(f"Added custom header: {name.strip()}: {value.strip()}")

    # Max word length: 0 means None (no limit)
    max_word_len = args.max_word_length if args.max_word_length > 0 else None

    return CrawlConfig(
        start_url=args.url,
        normalized_start_url=norm_url,
        base_scheme=parsed_start.scheme.lower(),
        base_netloc=parsed_start.netloc.lower(),
        depth=args.depth,
        offsite=args.offsite,
        exclude_patterns=exclusions,
        allowed_pattern=allowed_pattern,
        timeout=args.timeout,
        workers=args.workers,
        ignore_robots=args.ignore_robots,
        delay=args.delay,
        min_word_length=args.min_word_length,
        max_word_length=max_word_len,
        no_words=args.no_words,
        groups=args.groups,
        with_numbers=args.with_numbers,
        extract_email=args.email,
        extract_meta=args.meta,
        meta_temp_dir=args.meta_temp_dir,
        meta_timeout=args.meta_timeout,
        exiftool_path_hint=args.exiftool_path,
        keep_meta_files=args.keep,
        word_output_file=args.write,
        email_output_file=args.email_file,
        meta_output_file=args.meta_file,
        user_agent=args.ua,
        auth_type=args.auth_type,
        auth_user=args.auth_user,
        auth_pass=args.auth_pass,
        proxy_host=args.proxy_host,
        proxy_port=args.proxy_port,
        proxy_username=args.proxy_username,
        proxy_password=args.proxy_password,
        custom_headers=custom_headers,
        retries=args.retries,
        insecure_ssl=args.insecure,
        log_level=args.log_level
    )

# --- Main Execution ---

def main():
    """Main execution flow."""
    args = parse_arguments()

    # Configure logging level based on args
    log.setLevel(args.log_level)
    # Reconfigure handler level if basicConfig was already called
    for handler in logging.root.handlers:
         handler.setLevel(args.log_level)
    log.info(f"Log level set to: {logging.getLevelName(args.log_level)}")
    if not LXML_AVAILABLE and args.log_level <= logging.INFO:
         log.info("INFO: 'lxml' library not found. Using Python's built-in 'html.parser'.")
         log.info("      Install 'lxml' (pip install lxml) for potentially faster HTML parsing.")


    # Create configuration object
    config = create_config_from_args(args)

    # Find exiftool if metadata extraction is enabled
    exiftool_cmd: Optional[str] = None
    if config.extract_meta:
        exiftool_cmd = find_exiftool(config.exiftool_path_hint)
        if not exiftool_cmd:
            log.warning("Metadata extraction (-a) enabled, but a working 'exiftool' could not be found or verified.")
            log.warning("Metadata extraction will be skipped. Check path or install exiftool.")
            # Update config to reflect reality? Or let processor handle None exiftool_cmd.
            # Let's allow Crawler init, MetadataProcessor will handle None cmd.
        else:
             log.info(f"Using exiftool for metadata: {exiftool_cmd}")


    crawler: Optional[Crawler] = None
    output_writer: Optional[OutputWriter] = None
    try:
        crawler = Crawler(config, exiftool_cmd)
        output_writer = OutputWriter(config) # Init writer early

        crawler.run() # Start the crawl

        # If crawl completed (or was interrupted), process results
        output_writer.write_results(
            crawler.word_counts,
            crawler.group_counts,
            crawler.found_emails,
            crawler.found_metadata
        )

    except KeyboardInterrupt:
        # This might catch interrupt during initialization or output writing
        log.warning("\nCtrl+C detected during main execution phase. Exiting.")
        # Results might be partially written or not at all if interrupted late
        print("\nOperation interrupted.", file=sys.stderr)
        sys.exit(1) # Indicate interruption exit status

    except SystemExit as e:
        # Catch sys.exit calls for controlled exits (e.g., config errors)
        log.debug(f"SystemExit caught with code: {e.code}")
        sys.exit(e.code or 1) # Propagate exit code

    except Exception as e:
        # Catch any other unexpected critical errors
        log.critical(f"An unexpected critical error occurred in main: {e}", exc_info=True)
        sys.exit(1) # Exit with error status

    finally:
         # Any final cleanup if needed, e.g., closing resources not in context managers
         pass

    log.warning(f"--- CeWLPy {__version__} Finished ---")

if __name__ == "__main__":
    # For profiling or other entry point needs
    import threading # Need this for thread name logging format
    main()
