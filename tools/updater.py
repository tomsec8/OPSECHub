#!/usr/bin/env python3
"""
OPSECHub Rule Updater Script (External Utility)
This script updates local static DNR JSON rulesets inside OPSECHub/rules from upstream blocklists.
Location: tools/ (outside OPSECHub extension root directory).
"""

import os
import json
import re
import sys
import urllib.request
from datetime import datetime
from urllib.parse import urlparse

# Ensure UTF-8 output encoding on Windows terminals
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except AttributeError:
        pass

# Resolve OPSECHub paths relative to this tools/ directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OPSEC_HUB_DIR = os.path.join(BASE_DIR, 'OPSECHub')
RULES_DIR = os.path.join(OPSEC_HUB_DIR, 'rules')
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'updater_config.json')
METADATA_FILE = os.path.join(RULES_DIR, 'metadata.json')

# Chrome MV3 limit per ruleset file (up to 30,000 is safe per file)
MAX_RULES_PER_FILE = 30000
MAX_RULESETS_PER_CATEGORY = 10

def fetch_url(url):
    print(f"  Downloading: {url}")
    req = urllib.request.Request(
        url,
        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) OPSECHub-RuleUpdater/1.0'}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"  [ERROR] Failed to fetch {url}: {e}")
        return ""

def parse_adblock_rules(text, rule_id_start=1):
    rules = []
    rule_id = rule_id_start
    lines = text.splitlines()

    for line in lines:
        line = line.strip()
        if not line or line.startswith('!') or line.startswith('['):
            continue

        if line.startswith('@@'):
            # Strip exception rules for security
            continue

        if line.startswith('##') or '#@#' in line or '##+' in line:
            # Skip element hiding rules (handled via content scripts)
            continue

        url_filter = line
        is_domain_only = False

        if url_filter.startswith('||') and url_filter.endswith('^'):
            domain_candidate = url_filter[2:-1]
            if re.match(r'^[a-zA-Z0-9.\-]+$', domain_candidate):
                is_domain_only = True

        condition = {}
        if is_domain_only:
            condition['requestDomains'] = [domain_candidate]
        else:
            if not url_filter.isascii():
                continue
            condition['urlFilter'] = url_filter

        condition['resourceTypes'] = [
            "main_frame", "sub_frame", "stylesheet", "script", "image",
            "font", "object", "xmlhttprequest", "ping", "websocket", "other"
        ]

        rules.append({
            "id": rule_id,
            "priority": 1,
            "action": {"type": "block"},
            "condition": condition
        })
        rule_id += 1

    return rules

def update_rulesets():
    print("==================================================")
    print("🔒 OPSECHub External Rule Updater")
    print("==================================================")
    print(f"Target Directory: {RULES_DIR}\n")

    if not os.path.exists(CONFIG_FILE):
        print(f"[ERROR] Config file not found at {CONFIG_FILE}")
        sys.exit(1)

    with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
        config = json.load(f)

    os.makedirs(RULES_DIR, exist_ok=True)

    for profile in config.get('rulesets', []):
        profile_name = profile['name']
        print(f"\n--- Processing Profile: {profile_name} ---")

        all_rules = []
        for url in profile['sources']:
            raw_text = fetch_url(url)
            if raw_text:
                parsed = parse_adblock_rules(raw_text, rule_id_start=len(all_rules) + 1)
                all_rules.extend(parsed)
                print(f"  Parsed {len(parsed)} rules from source.")

        print(f"Total compiled rules for {profile_name}: {len(all_rules)}")

        # Split into chunks of MAX_RULES_PER_FILE
        target_dir = os.path.join(RULES_DIR, 'Core', profile_name.replace('Core_', ''))
        os.makedirs(target_dir, exist_ok=True)

        chunks = [all_rules[i:i + MAX_RULES_PER_FILE] for i in range(0, len(all_rules), MAX_RULES_PER_FILE)]
        chunks = chunks[:MAX_RULESETS_PER_CATEGORY]

        for idx in range(1, MAX_RULESETS_PER_CATEGORY + 1):
            file_name = f"{profile_name}_{idx}.json"
            file_path = os.path.join(target_dir, file_name)

            if idx <= len(chunks):
                chunk = chunks[idx - 1]
                # Re-index rule IDs for consistency
                for local_idx, r in enumerate(chunk, 1):
                    r['id'] = local_idx
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(chunk, f, indent=2)
                print(f"  Saved: {file_name} ({len(chunk)} rules)")
            else:
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump([], f, indent=2)
                print(f"  Saved: {file_name} (0 rules - placeholder)")

    # Update metadata.json with timestamp
    if os.path.exists(METADATA_FILE):
        try:
            with open(METADATA_FILE, 'r', encoding='utf-8') as f:
                meta = json.load(f)
            today_str = datetime.now().strftime("%Y-%m-%d")
            for profile in config.get('rulesets', []):
                pname = profile['name']
                if pname in meta:
                    meta[pname]['lastUpdated'] = today_str
            with open(METADATA_FILE, 'w', encoding='utf-8') as f:
                json.dump(meta, f, indent=2)
            print(f"\n📝 Updated metadata.json with date: {today_str}")
        except Exception as meta_err:
            print(f"[WARNING] Failed to update metadata.json date: {meta_err}")

    print("\n✅ All rulesets updated successfully!")

if __name__ == '__main__':
    update_rulesets()
