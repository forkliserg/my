"""Config processing module with all the main processing logic."""

import os
import sys
import concurrent.futures
import base64
from typing import List, Tuple, Optional
import math

# Add the source directory to the path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from config.settings import URLS, URLS_BASE64, URLS_YAML, EXTRA_URLS_FOR_BYPASS, DEFAULT_MAX_WORKERS
from fetchers.fetcher import fetch_data, build_session
from fetchers.daily_repo_fetcher import fetch_configs_from_daily_repo
from utils.file_utils import save_to_local_file, load_from_local_file, split_config_file, deduplicate_configs, prepare_config_content, filter_secure_configs, has_insecure_setting, apply_sni_cidr_filter
from utils.logger import log


def download_all_configs(output_dir: str = "../githubmirror") -> Tuple[List[str], List[str]]:
    """Downloads all configs from all sources. Returns (all_configs, extra_bypass_configs)."""
    all_configs = []
    extra_bypass_configs = []

    # Create output directories
    os.makedirs(f"{output_dir}/default", exist_ok=True)
    os.makedirs(f"{output_dir}/bypass", exist_ok=True)
    os.makedirs(f"{output_dir}/bypass-unsecure", exist_ok=True)
    os.makedirs(f"{output_dir}/split-by-protocols", exist_ok=True)
    os.makedirs("../qr-codes", exist_ok=True)

    # Download from regular URLs
    if URLS:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(DEFAULT_MAX_WORKERS, max(1, len(URLS)))) as executor:
            futures = [executor.submit(fetch_data, url) for url in URLS]
            for future in concurrent.futures.as_completed(futures):
                try:
                    content = future.result()
                    configs = prepare_config_content(content)
                    all_configs.extend(configs)
                except Exception as e:
                    log(f"Error downloading from regular URL: {str(e)[:200]}...")

    # Download from base64 URLs
    if URLS_BASE64:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(DEFAULT_MAX_WORKERS, max(1, len(URLS_BASE64)))) as executor:
            futures = [executor.submit(fetch_data, url) for url in URLS_BASE64]
            for future in concurrent.futures.as_completed(futures):
                try:
                    content = future.result()
                    # Decode base64 content
                    decoded_bytes = base64.b64decode(content.strip())
                    decoded_content = decoded_bytes.decode('utf-8')
                    configs = prepare_config_content(decoded_content)
                    all_configs.extend(configs)
                except Exception as e:
                    log(f"Error downloading from base64 URL: {str(e)[:200]}...")

    # Download from extra bypass URLs (these should be added to bypass configs without SNI/CIDR filtering)
    if EXTRA_URLS_FOR_BYPASS:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(DEFAULT_MAX_WORKERS, max(1, len(EXTRA_URLS_FOR_BYPASS)))) as executor:
            futures = [executor.submit(fetch_data, url) for url in EXTRA_URLS_FOR_BYPASS]
            for future in concurrent.futures.as_completed(futures):
                try:
                    content = future.result()
                    configs = prepare_config_content(content)
                    extra_bypass_configs.extend(configs)  # Store separately for bypass processing
                except Exception as e:
                    log(f"Error downloading from extra bypass URL: {str(e)[:200]}...")

    # Download and convert from YAML URLs
    if URLS_YAML:
        from fetchers.yaml_converter import convert_yaml_to_vpn_configs
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(DEFAULT_MAX_WORKERS, max(1, len(URLS_YAML)))) as executor:
            futures = [executor.submit(fetch_data, url) for url in URLS_YAML]
            for future in concurrent.futures.as_completed(futures):
                try:
                    yaml_content = future.result()
                    vpn_configs = convert_yaml_to_vpn_configs(yaml_content)
                    if vpn_configs:
                        all_configs.extend(vpn_configs)
                except Exception as e:
                    log(f"Error downloading or converting YAML: {str(e)[:200]}...")

    # Download from daily-updated repository
    try:
        daily_configs = fetch_configs_from_daily_repo()
        all_configs.extend(daily_configs)
        log(f"Downloaded {len(daily_configs)} configs from daily-updated repository")
    except Exception as e:
        log(f"Error downloading from daily-updated repository: {str(e)[:200]}...")

    return all_configs, extra_bypass_configs


def create_all_configs_file(all_configs: List[str], output_dir: str = "../githubmirror") -> str:
    """Creates the all.txt file with all unique configs."""
    unique_configs = deduplicate_configs(all_configs)
    all_txt_path = f"{output_dir}/default/all.txt"
    
    try:
        with open(all_txt_path, "w", encoding="utf-8") as f:
            f.write("\n".join(unique_configs))
        log(f"Created {all_txt_path} with {len(unique_configs)} unique configs")
        return all_txt_path
    except Exception as e:
        log(f"Error creating all.txt: {e}")
        return ""


def create_secure_configs_file(all_configs: List[str], output_dir: str = "../githubmirror") -> str:
    """Creates the all-secure.txt file with only secure configs."""
    secure_configs = filter_secure_configs(all_configs)
    unique_secure_configs = deduplicate_configs(secure_configs)
    all_secure_txt_path = f"{output_dir}/default/all-secure.txt"
    
    try:
        with open(all_secure_txt_path, "w", encoding="utf-8") as f:
            f.write("\n".join(unique_secure_configs))
        log(f"Created {all_secure_txt_path} with {len(unique_secure_configs)} unique secure configs")
        return all_secure_txt_path
    except Exception as e:
        log(f"Error creating all-secure.txt: {e}")
        return ""




def split_configs_to_files(configs: List[str], output_dir: str, filename_prefix: str, max_configs_per_file: int = 300) -> List[str]:
    """Splits configs into multiple files with a given prefix."""
    created_files = []
    
    num_configs = len(configs)
    if not num_configs:
        return []

    # Calculate the number of files needed, rounding up
    num_files = math.ceil(num_configs / max_configs_per_file)
    
    for i in range(int(num_files)):
        start = i * max_configs_per_file
        end = start + max_configs_per_file
        chunk = configs[start:end]
        
        filename = f"{output_dir}/{filename_prefix}-{i + 1}.txt"
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write("\n".join(chunk))
            log(f"Created {filename} with {len(chunk)} configs")
            created_files.append(filename)
        except Exception as e:
            log(f"Error creating {filename}: {e}")
            
    return created_files


def create_protocol_split_files(all_configs: List[str], output_dir: str = "../githubmirror") -> List[Tuple[str, str]]:
    """Creates protocol-specific files in the split-by-protocols folder, both secure and unsecure versions."""
    # Define supported protocols
    protocols = ['vless', 'vmess', 'trojan', 'ss', 'ssr', 'tuic', 'hysteria', 'hysteria2', 'hy2']

    # Separate configs by protocol and security
    protocol_configs = {protocol: [] for protocol in protocols}
    protocol_secure_configs = {protocol: [] for protocol in protocols}

    for config in all_configs:
        # Determine the protocol from the config line
        config_lower = config.lower()
        matched_protocol = None

        for protocol in protocols:
            if config_lower.startswith(f"{protocol}://"):
                matched_protocol = protocol
                break

        if matched_protocol:
            # Add to unsecure version (all configs for this protocol)
            protocol_configs[matched_protocol].append(config)

            # Add to secure version only if it's secure
            if not has_insecure_setting(config):
                protocol_secure_configs[matched_protocol].append(config)

    # Create file pairs for upload
    file_pairs = []

    # Create unsecure protocol files (all configs for each protocol)
    for protocol, configs in protocol_configs.items():
        if configs:  # Only create file if there are configs for this protocol
            filename = f"{protocol}.txt"
            filepath = os.path.join(f"{output_dir}/split-by-protocols", filename)

            # Remove duplicates while preserving order
            unique_configs = list(dict.fromkeys(configs))  # Remove duplicates while preserving order

            try:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write("\n".join(unique_configs))
                log(f"Created file {filepath} with {len(unique_configs)} configs ({protocol})")

                file_pairs.append((filepath, f"githubmirror/split-by-protocols/{filename}"))
            except Exception as e:
                log(f"Error creating {filepath}: {e}")

    # Create secure protocol files (only secure configs for each protocol)
    for protocol, configs in protocol_secure_configs.items():
        if configs:  # Only create file if there are secure configs for this protocol
            filename = f"{protocol}-secure.txt"
            filepath = os.path.join(f"{output_dir}/split-by-protocols", filename)

            # Remove duplicates while preserving order
            unique_configs = list(dict.fromkeys(configs))  # Remove duplicates while preserving order

            try:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write("\n".join(unique_configs))
                log(f"Created file {filepath} with {len(unique_configs)} secure configs ({protocol})")

                file_pairs.append((filepath, f"githubmirror/split-by-protocols/{filename}"))
            except Exception as e:
                log(f"Error creating {filepath}: {e}")

    return file_pairs


def process_all_configs(output_dir: str = "../githubmirror") -> List[Tuple[str, str]]:
    """Main processing function that orchestrates the entire config generation process."""
    # Step 1: Download all configs from all sources
    log("Downloading all configs from all sources...")
    all_configs, extra_bypass_configs = download_all_configs(output_dir)
    log(f"Downloaded {len(all_configs)} total configs and {len(extra_bypass_configs)} extra bypass configs")

    # Step 2: Create all.txt file (all unique configs)
    log("Creating all.txt file...")
    all_txt_file = create_all_configs_file(all_configs, output_dir)

    # Step 3: Create all-secure.txt file (only secure configs)
    log("Creating all-secure.txt file...")
    all_secure_txt_file = create_secure_configs_file(all_configs, output_dir)

    # Step 4: Create bypass-all.txt file (SNI/CIDR bypass configs: regular + base64 + yaml with SNI/CIDR filtering + extra bypass without SNI/CIDR filtering)
    log("Creating bypass-all.txt file...")
    # Apply SNI/CIDR filtering to main configs (regular + base64 + yaml)
    sni_cidr_filtered_configs = apply_sni_cidr_filter(all_configs, filter_secure=True)
    # Add extra bypass configs (without SNI/CIDR filtering but with secure filtering)
    secure_extra_bypass_configs = filter_secure_configs(extra_bypass_configs)
    all_bypass_configs = sni_cidr_filtered_configs + secure_extra_bypass_configs
    unique_bypass_configs = deduplicate_configs(all_bypass_configs)

    bypass_all_txt_path = f"{output_dir}/bypass/bypass-all.txt"
    try:
        with open(bypass_all_txt_path, "w", encoding="utf-8") as f:
            f.write("\n".join(unique_bypass_configs))
        log(f"Created {bypass_all_txt_path} with {len(unique_bypass_configs)} unique bypass configs")
        bypass_all_txt_file = bypass_all_txt_path
    except Exception as e:
        log(f"Error creating bypass-all.txt: {e}")
        bypass_all_txt_file = ""

    # Step 5: Split bypass configs into multiple files
    log("Splitting bypass configs into multiple files...")
    bypass_files = split_configs_to_files(unique_bypass_configs, f"{output_dir}/bypass", "bypass")

    # Step 6: Create bypass-unsecure-all.txt file (SNI/CIDR bypass configs including insecure)
    log("Creating bypass-unsecure-all.txt file...")
    # Apply SNI/CIDR filtering to main configs (regular + base64 + yaml) without secure filtering
    sni_cidr_filtered_unsecure_configs = apply_sni_cidr_filter(all_configs, filter_secure=False)
    # Add extra bypass configs (without SNI/CIDR filtering and without secure filtering)
    all_bypass_unsecure_configs = sni_cidr_filtered_unsecure_configs + extra_bypass_configs
    unique_bypass_unsecure_configs = deduplicate_configs(all_bypass_unsecure_configs)

    bypass_unsecure_all_txt_path = f"{output_dir}/bypass-unsecure/bypass-unsecure-all.txt"
    try:
        with open(bypass_unsecure_all_txt_path, "w", encoding="utf-8") as f:
            f.write("\n".join(unique_bypass_unsecure_configs))
        log(f"Created {bypass_unsecure_all_txt_path} with {len(unique_bypass_unsecure_configs)} unique unsecure bypass configs")
        bypass_unsecure_all_txt_file = bypass_unsecure_all_txt_path
    except Exception as e:
        log(f"Error creating bypass-unsecure-all.txt: {e}")
        bypass_unsecure_all_txt_file = ""

    # Step 7: Split bypass-unsecure configs into multiple files
    log("Splitting bypass-unsecure configs into multiple files...")
    bypass_unsecure_files = split_configs_to_files(unique_bypass_unsecure_configs, f"{output_dir}/bypass-unsecure", "bypass-unsecure")

    # Step 8: Create protocol-specific files
    log("Creating protocol-specific files...")
    all_protocol_configs = all_configs + extra_bypass_configs  # Include extra bypass configs in protocol splitting
    protocol_files = create_protocol_split_files(all_protocol_configs, output_dir)

    # Prepare file pairs for upload
    file_pairs = []

    # Add default files
    if all_txt_file:
        file_pairs.append((all_txt_file, "githubmirror/default/all.txt"))
    if all_secure_txt_file:
        file_pairs.append((all_secure_txt_file, "githubmirror/default/all-secure.txt"))

    # Add bypass files
    if bypass_all_txt_file:
        file_pairs.append((bypass_all_txt_file, "githubmirror/bypass/bypass-all.txt"))
    for bypass_file in bypass_files:
        filename = os.path.basename(bypass_file)
        file_pairs.append((bypass_file, f"githubmirror/bypass/{filename}"))

    # Add bypass-unsecure files
    if bypass_unsecure_all_txt_file:
        file_pairs.append((bypass_unsecure_all_txt_file, "githubmirror/bypass-unsecure/bypass-unsecure-all.txt"))
    for bypass_unsecure_file in bypass_unsecure_files:
        filename = os.path.basename(bypass_unsecure_file)
        file_pairs.append((bypass_unsecure_file, f"githubmirror/bypass-unsecure/{filename}"))

    # Add protocol files (already in correct format)
    file_pairs.extend(protocol_files)

    return file_pairs