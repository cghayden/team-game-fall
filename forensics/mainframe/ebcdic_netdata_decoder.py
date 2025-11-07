#!/usr/bin/env python3
"""
EBCDIC NETDATA Decoder for Mainframe Spool Files
Decodes EBCDIC-encoded mainframe spool/NETDATA files from base64 wrapper
"""

import os
import base64
import struct
from pathlib import Path

def decode_ebcdic_netdata():
    """Decode EBCDIC NETDATA file and search for specific content"""
    
    file_path = "/Users/corey/team-game-fall/forensics/mainframe/ARCHIVE.NETDATA.XMI"
    
    print("🏛️  MAINFRAME EBCDIC NETDATA DECODER")
    print("=" * 60)
    
    # Step 1: Decode base64
    with open(file_path, 'rb') as f:
        content = f.read()
    
    lines = content.split(b'\n')
    base64_content = b''.join(line.strip() for line in lines if line.strip())
    decoded = base64.b64decode(base64_content)
    
    print(f"📊 File size: {len(content):,} bytes")
    print(f"🔓 Decoded size: {len(decoded):,} bytes")
    
    # Step 2: Decode EBCDIC using cp037 (IBM EBCDIC US-Canada)
    print(f"\n🔤 DECODING EBCDIC (CP037)")
    print("-" * 40)
    
    try:
        # Decode the entire content as EBCDIC
        ebcdic_text = decoded.decode('cp037', errors='replace')
        
        print(f"✅ EBCDIC decode successful: {len(ebcdic_text):,} characters")
        
        # Save decoded EBCDIC content
        output_dir = "/tmp/ebcdic_decoded"
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        ebcdic_file = os.path.join(output_dir, "netdata_ebcdic.txt")
        with open(ebcdic_file, 'w', encoding='utf-8') as f:
            f.write(ebcdic_text)
        
        print(f"💾 EBCDIC content saved to: {ebcdic_file}")
        
        # Step 3: Search for NETDATA headers and metadata
        print(f"\n🔍 SEARCHING FOR NETDATA HEADERS")
        print("-" * 40)
        
        search_netdata_headers(ebcdic_text)
        
        # Step 4: Search for FIREID accounts
        print(f"\n🔍 SEARCHING FOR FIREID ACCOUNTS")
        print("-" * 40)
        
        search_fireid_accounts(ebcdic_text, output_dir)
        
        # Step 5: Search for VIPER1
        print(f"\n🔍 SEARCHING FOR 'VIPER1'")
        print("-" * 40)
        
        search_viper1(ebcdic_text, output_dir)
        
        # Step 6: Extract user data
        print(f"\n👥 EXTRACTING USER DATA")
        print("-" * 40)
        
        extract_user_data(ebcdic_text, output_dir)
        
        # Step 7: General analysis
        print(f"\n📈 GENERAL CONTENT ANALYSIS")
        print("-" * 40)
        
        analyze_content(ebcdic_text, output_dir)
        
    except Exception as e:
        print(f"❌ EBCDIC decode failed: {e}")
        
        # Try other EBCDIC code pages
        other_codepages = ['cp500', 'cp875', 'cp1026', 'cp1140']
        for cp in other_codepages:
            try:
                print(f"🔄 Trying {cp}...")
                ebcdic_text = decoded.decode(cp, errors='replace')
                print(f"✅ {cp} decode successful")
                break
            except Exception as e2:
                print(f"❌ {cp} failed: {e2}")

def search_netdata_headers(text):
    """Search for NETDATA headers and metadata fields"""
    
    headers = ['ORIGNODE', 'ORIGUID', 'DESTNODE', 'DESTUID', 'NETDATA', 'INMR01', 'INMR02']
    
    found_headers = {}
    
    for header in headers:
        positions = []
        pos = 0
        while True:
            pos = text.find(header, pos)
            if pos == -1:
                break
            positions.append(pos)
            pos += len(header)
        
        if positions:
            found_headers[header] = positions
            print(f"  📍 {header}: {len(positions)} occurrences at positions {positions[:5]}{'...' if len(positions) > 5 else ''}")
            
            # Show context around first occurrence
            first_pos = positions[0]
            start = max(0, first_pos - 50)
            end = min(len(text), first_pos + len(header) + 50)
            context = text[start:end].replace('\n', '\\n').replace('\r', '\\r')
            print(f"      Context: ...{context}...")
    
    if not found_headers:
        print("  ❌ No NETDATA headers found")

def search_fireid_accounts(text, output_dir):
    """Search for FIREID accounts"""
    
    import re
    
    # Search for FIREID pattern
    fireid_patterns = [
        r'FIREID\w*',
        r'FIRE\w+',
        r'\bFIRE[A-Z0-9]+\b',
    ]
    
    all_fireids = set()
    
    for pattern in fireid_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        all_fireids.update(matches)
    
    if all_fireids:
        fireids = sorted(all_fireids)
        print(f"  🔥 Found {len(fireids)} FIREID-related entries:")
        for fireid in fireids:
            print(f"    {fireid}")
            
            # Find context around each FIREID
            for match in re.finditer(re.escape(fireid), text, re.IGNORECASE):
                pos = match.start()
                start = max(0, pos - 100)
                end = min(len(text), pos + len(fireid) + 100)
                context = text[start:end].replace('\n', ' ').replace('\r', ' ')
                print(f"      Context: ...{context}...")
        
        # Save FIREID results
        fireid_file = os.path.join(output_dir, "fireid_accounts.txt")
        with open(fireid_file, 'w') as f:
            f.write("FIREID ACCOUNTS FOUND:\n")
            f.write("=" * 30 + "\n\n")
            for fireid in fireids:
                f.write(f"{fireid}\n")
        
        print(f"  💾 FIREID accounts saved to: {fireid_file}")
    else:
        print("  ❌ No FIREID accounts found")

def search_viper1(text, output_dir):
    """Search for VIPER1 string"""
    
    import re
    
    # Search for VIPER1 (case insensitive)
    viper1_matches = []
    
    for match in re.finditer(r'VIPER1', text, re.IGNORECASE):
        pos = match.start()
        start = max(0, pos - 200)
        end = min(len(text), pos + 6 + 200)
        context = text[start:end]
        
        viper1_matches.append({
            'position': pos,
            'context': context
        })
    
    if viper1_matches:
        print(f"  🐍 Found {len(viper1_matches)} occurrences of 'VIPER1':")
        
        for i, match in enumerate(viper1_matches):
            print(f"    Match {i+1} at position {match['position']}:")
            # Clean up context for display
            clean_context = match['context'].replace('\n', '\\n').replace('\r', '\\r')
            print(f"      {clean_context[:150]}{'...' if len(clean_context) > 150 else ''}")
        
        # Save VIPER1 results
        viper1_file = os.path.join(output_dir, "viper1_findings.txt")
        with open(viper1_file, 'w') as f:
            f.write("VIPER1 SEARCH RESULTS:\n")
            f.write("=" * 30 + "\n\n")
            for i, match in enumerate(viper1_matches):
                f.write(f"Match {i+1} at position {match['position']}:\n")
                f.write(f"{match['context']}\n")
                f.write("-" * 50 + "\n\n")
        
        print(f"  💾 VIPER1 findings saved to: {viper1_file}")
    else:
        print("  ❌ No 'VIPER1' string found")

def extract_user_data(text, output_dir):
    """Extract and analyze user-related data"""
    
    import re
    
    # Look for user patterns
    user_patterns = [
        r'\b[A-Z][A-Z0-9]{2,7}\b',  # Typical mainframe user IDs
        r'\b[A-Z]{3,8}[0-9]{0,3}\b',  # User ID patterns
        r'USER\w+',
        r'ID\w+',
    ]
    
    potential_users = set()
    
    for pattern in user_patterns:
        matches = re.findall(pattern, text)
        potential_users.update(matches)
    
    # Filter out common false positives
    filtered_users = []
    exclude_words = {'THE', 'AND', 'FOR', 'NOT', 'BUT', 'YOU', 'ALL', 'CAN', 'HER', 'WAS', 'ONE', 'OUR', 'HAD', 'BY ', 'UP ', 'DO ', 'NO ', 'IF ', 'OF ', 'TO ', 'IN ', 'IT ', 'ON ', 'BE ', 'AT '}
    
    for user in potential_users:
        if len(user) >= 3 and user not in exclude_words:
            filtered_users.append(user)
    
    if filtered_users:
        sorted_users = sorted(set(filtered_users))
        print(f"  👤 Found {len(sorted_users)} potential user identifiers:")
        
        for user in sorted_users[:20]:  # Show first 20
            print(f"    {user}")
        
        if len(sorted_users) > 20:
            print(f"    ... and {len(sorted_users) - 20} more")
        
        # Save user data
        users_file = os.path.join(output_dir, "potential_users.txt")
        with open(users_file, 'w') as f:
            f.write("POTENTIAL USER IDENTIFIERS:\n")
            f.write("=" * 35 + "\n\n")
            for user in sorted_users:
                f.write(f"{user}\n")
        
        print(f"  💾 User data saved to: {users_file}")
    else:
        print("  ❌ No user identifiers found")

def analyze_content(text, output_dir):
    """General content analysis"""
    
    import re
    
    # Statistics
    lines = text.split('\n')
    non_empty_lines = [line for line in lines if line.strip()]
    
    print(f"  📊 Total lines: {len(lines):,}")
    print(f"  📊 Non-empty lines: {len(non_empty_lines):,}")
    print(f"  📊 Total characters: {len(text):,}")
    
    # Look for email patterns
    emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)
    if emails:
        unique_emails = sorted(set(emails))
        print(f"  📧 Email addresses found: {len(unique_emails)}")
        for email in unique_emails[:10]:
            print(f"    {email}")
        if len(unique_emails) > 10:
            print(f"    ... and {len(unique_emails) - 10} more")
    
    # Look for dates
    dates = re.findall(r'\d{2}[/-]\d{2}[/-]\d{2,4}|\d{4}[/-]\d{2}[/-]\d{2}', text)
    if dates:
        unique_dates = sorted(set(dates))
        print(f"  📅 Dates found: {unique_dates[:10]}")
    
    # Save full analysis
    analysis_file = os.path.join(output_dir, "full_ebcdic_content.txt")
    with open(analysis_file, 'w', encoding='utf-8') as f:
        f.write("FULL EBCDIC DECODED CONTENT\n")
        f.write("=" * 40 + "\n\n")
        f.write(text)
    
    print(f"  💾 Full content saved to: {analysis_file}")
    print(f"\n✅ Analysis complete! Check {output_dir} for all extracted data")

if __name__ == "__main__":
    decode_ebcdic_netdata()