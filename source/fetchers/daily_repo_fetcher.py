"""Module for fetching VPN configs from daily-updated repository."""

import datetime
import base64
from typing import List, Optional
from urllib.parse import urljoin
import sys
import os

# Add the source directory to the path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fetchers.fetcher import fetch_data
from utils.logger import log
from utils.file_utils import prepare_config_content


def generate_date_filename(date: datetime.date) -> str:
    """Generate filename in format v2YYYYMMDD based on the given date."""
    return f"v2{date.strftime('%Y%m%d')}"


def fetch_daily_configs(base_url: str, date: datetime.date) -> Optional[List[str]]:
    """Fetch configs from daily-updated repository for a specific date."""
    filename = generate_date_filename(date)
    url = urljoin(base_url, filename)

    try:
        content = fetch_data(url)
        # Check if content is base64-encoded (common for VPN config repositories)
        try:
            # Try to decode as base64
            decoded_bytes = base64.b64decode(content.strip())
            decoded_content = decoded_bytes.decode('utf-8')
            configs = prepare_config_content(decoded_content)
        except Exception:
            # If base64 decoding fails, treat as plain text
            configs = prepare_config_content(content)

        log(f"Successfully fetched {len(configs)} configs from {url}")
        return configs
    except Exception as e:
        log(f"Error fetching configs from {url}: {str(e)[:200]}...")
        return None


def fetch_daily_configs_with_timezone_fallback(base_url: str, target_date: Optional[datetime.date] = None) -> List[str]:
    """Fetch configs from daily-updated repository with timezone fallback logic.

    Tries to fetch configs for:
    1. Target date (default: today)
    2. Day before target date
    3. Day after target date

    Returns the first successful result, or empty list if all attempts fail.
    """
    if target_date is None:
        target_date = datetime.date.today()

    # Define the dates to try in order of preference
    dates_to_try = [
        target_date,                    # Current date
        target_date - datetime.timedelta(days=1),  # Day before
        target_date + datetime.timedelta(days=1)   # Day after
    ]

    all_configs = []

    for date in dates_to_try:
        configs = fetch_daily_configs(base_url, date)
        if configs is not None:
            log(f"Successfully fetched configs for date {date} ({generate_date_filename(date)})")
            all_configs.extend(configs)
            # We found configs for this date, so we can return them
            # (We could also continue to collect configs from other dates if needed)
            break

    if not all_configs:
        log(f"No configs found for dates: {[generate_date_filename(d) for d in dates_to_try]}")

    return all_configs


def fetch_configs_from_daily_repo(base_url: str = "https://raw.githubusercontent.com/free-nodes/v2rayfree/refs/heads/main/") -> List[str]:
    """Main function to fetch configs from the daily-updated repository."""
    log(f"Fetching configs from daily-updated repository: {base_url}")
    configs = fetch_daily_configs_with_timezone_fallback(base_url)
    log(f"Total configs fetched from daily repository: {len(configs)}")
    return configs