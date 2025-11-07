#!/usr/bin/env python3
"""
EBCDIC CP500 Decoder for NETDATA
Uses codecs module with cp500 encoding to properly decode EBCDIC mainframe data
"""

import os
import base64
import codecs
import re
from pathlib import Path

def ebcdic_cp500_decode():
    """Decode using CP500 EBCDIC and search for FIREID and VIPER1"""
    
    file_path = "/Users/corey/team-game-fall/forensics/mainframe/ARCHIVE.NETDATA.XMI"
    
    print("🏛️  EBCDIC CP500 DECODER")
    print("=" * 40)
    
    # Step 1: Read and decode base64
    with open(file_path, 'rb') as f:
        content = f.read()
    
    print(f"📊 Original file size: {len(content):,} bytes")
    
    # Decode base64
    lines = content.split(b'\n')
    base64_content = b''.join(line.strip() for line in lines if line.strip())
    decoded_binary = base64.b64decode(base64_content)
    
    print(f"🔓 Base64 decoded size: {len(decoded_binary):,} bytes")
    
    # Step 2: Decode EBCDIC using CP500
    print(f"\n🔤 DECODING WITH CP500 (IBM EBCDIC)")
    print("-" * 40)
    
    try:
        # Method 1: Using codecs.decode
        ebcdic_text = codecs.decode(decoded_binary, "cp500")
        
        print(f"✅ CP500 decode successful: {len(ebcdic_text):,} characters")
        
        # Save decoded content
        output_dir = "/tmp/cp500_decoded"
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        full_content_file = os.path.join(output_dir, "netdata_cp500.txt")
        with open(full_content_file, 'w', encoding='utf-8') as f:
            f.write(ebcdic_text)
        
        print(f"💾 Full CP500 content saved to: {full_content_file}")
        
        # Step 3: Search for FIREID accounts
        print(f"\n🔍 SEARCHING FOR FIREID ACCOUNTS")
        print("-" * 40)
        search_fireid(ebcdic_text, output_dir)
        
        # Step 4: Search for VIPER1
        print(f"\n🔍 SEARCHING FOR VIPER1")
        print("-" * 40)
        search_viper1(ebcdic_text, output_dir)
        
        # Step 5: Extract user data
        print(f"\n👥 EXTRACTING USER INFORMATION")
        print("-" * 40)
        extract_users(ebcdic_text, output_dir)
        
        # Step 6: Look for email addresses
        print(f"\n📧 SEARCHING FOR EMAIL ADDRESSES")
        print("-" * 40)
        search_emails(ebcdic_text, output_dir)
        
        # Step 7: Show sample content
        print(f"\n📝 SAMPLE CONTENT PREVIEW")
        print("-" * 40)
        preview_content(ebcdic_text)
        
    except Exception as e:
        print(f"❌ CP500 decode failed: {e}")
        
        # Try alternative method with error handling
        try:
            print(f"🔄 Trying alternative decode with error handling...")
            ebcdic_text = decoded_binary.decode('cp500', errors='replace')
            print(f"✅ Alternative decode successful with error replacement")
            
            # Still search even with replacement characters
            search_fireid(ebcdic_text, output_dir)
            search_viper1(ebcdic_text, output_dir)
            
        except Exception as e2:
            print(f"❌ Alternative decode also failed: {e2}")

def search_fireid(text, output_dir):
    """Search for FIREID accounts"""
    
    # Multiple patterns to catch variations
    patterns = [
        r'FIREID\w*',           # FIREID followed by word characters
        r'FIRE\w*ID\w*',        # FIRE...ID patterns
        r'\bFIRE[A-Z0-9]+\b',   # FIRE followed by alphanumeric
        r'[A-Z0-9]*FIRE[A-Z0-9]*', # FIRE embedded in identifiers
    ]
    
    all_matches = set()
    
    for pattern in patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        all_matches.update(matches)
    
    if all_matches:
        sorted_matches = sorted(all_matches)
        print(f"  🔥 Found {len(sorted_matches)} FIREID-related entries:")
        
        for match in sorted_matches:
            print(f"    {match}")
            
            # Show context around each match
            for found in re.finditer(re.escape(match), text, re.IGNORECASE):
                pos = found.start()
                start = max(0, pos - 150)
                end = min(len(text), pos + len(match) + 150)
                context = text[start:end].replace('\n', ' ').replace('\r', ' ')
                clean_context = ' '.join(context.split())  # Clean whitespace
                print(f"      Context: ...{clean_context}...")
                break  # Show only first occurrence context
        
        # Save FIREID results
        fireid_file = os.path.join(output_dir, "fireid_findings.txt")
        with open(fireid_file, 'w', encoding='utf-8') as f:
            f.write("FIREID SEARCH RESULTS\n")
            f.write("=" * 30 + "\n\n")
            for match in sorted_matches:
                f.write(f"Found: {match}\n")
                
                # Add full context for each match
                for found in re.finditer(re.escape(match), text, re.IGNORECASE):
                    pos = found.start()
                    start = max(0, pos - 300)
                    end = min(len(text), pos + len(match) + 300)
                    context = text[start:end]
                    f.write(f"Context:\n{context}\n")
                    f.write("-" * 50 + "\n\n")
                    break
        
        print(f"  💾 FIREID results saved to: fireid_findings.txt")
    else:
        print(f"  ❌ No FIREID accounts found")

def search_viper1(text, output_dir):
    """Search for VIPER1 and VIPER variations"""
    
    patterns = [
        r'VIPER1\b',
        r'VIPER\w*',
        r'\bVIPER[A-Z0-9]*\b',
    ]
    
    all_matches = set()
    match_contexts = []
    
    for pattern in patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            matched_text = match.group()
            all_matches.add(matched_text)
            
            # Get context
            pos = match.start()
            start = max(0, pos - 200)
            end = min(len(text), pos + len(matched_text) + 200)
            context = text[start:end]
            
            match_contexts.append({
                'match': matched_text,
                'position': pos,
                'context': context
            })
    
    if all_matches:
        print(f"  🐍 Found {len(all_matches)} VIPER-related entries:")
        
        for match in sorted(all_matches):
            print(f"    {match}")
        
        print(f"\n  📍 Match locations:")
        for ctx in match_contexts[:5]:  # Show first 5 contexts
            clean_context = ' '.join(ctx['context'].replace('\n', ' ').replace('\r', ' ').split())
            print(f"    '{ctx['match']}' at position {ctx['position']}")
            print(f"      Context: ...{clean_context[:200]}...")
        
        # Save VIPER results
        viper_file = os.path.join(output_dir, "viper_findings.txt")
        with open(viper_file, 'w', encoding='utf-8') as f:
            f.write("VIPER SEARCH RESULTS\n")
            f.write("=" * 30 + "\n\n")
            for ctx in match_contexts:
                f.write(f"Found: {ctx['match']} at position {ctx['position']}\n")
                f.write(f"Context:\n{ctx['context']}\n")
                f.write("-" * 50 + "\n\n")
        
        print(f"  💾 VIPER results saved to: viper_findings.txt")
    else:
        print(f"  ❌ No VIPER1 or VIPER entries found")

def extract_users(text, output_dir):
    """Extract potential user identifiers"""
    
    # Common mainframe user ID patterns
    patterns = [
        r'\b[A-Z][A-Z0-9]{2,7}\b',      # Standard user IDs
        r'\b[A-Z]{3,8}[0-9]{0,3}\b',    # User ID with optional numbers
        r'USER\w+',                      # USER prefixed identifiers
        r'ID[A-Z0-9]+',                 # ID prefixed identifiers
    ]
    
    potential_users = set()
    
    for pattern in patterns:
        matches = re.findall(pattern, text)
        potential_users.update(matches)
    
    # Filter out common false positives
    exclude = {
        'THE', 'AND', 'FOR', 'NOT', 'BUT', 'YOU', 'ALL', 'CAN', 'HER', 
        'WAS', 'ONE', 'OUR', 'HAD', 'WITH', 'HAVE', 'THIS', 'WILL', 
        'ARE', 'FROM', 'THEY', 'KNOW', 'WANT', 'BEEN', 'GOOD', 'MUCH',
        'SOME', 'TIME', 'VERY', 'WHEN', 'COME', 'HERE', 'HOW', 'JUST',
        'LIKE', 'LONG', 'MAKE', 'MANY', 'OVER', 'SUCH', 'TAKE', 'THAN',
        'THEM', 'WELL', 'WERE'
    }
    
    filtered_users = [user for user in potential_users if user not in exclude and len(user) >= 3]
    
    if filtered_users:
        sorted_users = sorted(set(filtered_users))
        print(f"  👤 Found {len(sorted_users)} potential user identifiers:")
        
        for user in sorted_users[:20]:  # Show first 20
            print(f"    {user}")
        
        if len(sorted_users) > 20:
            print(f"    ... and {len(sorted_users) - 20} more")
        
        # Save user identifiers
        users_file = os.path.join(output_dir, "user_identifiers.txt")
        with open(users_file, 'w', encoding='utf-8') as f:
            f.write("POTENTIAL USER IDENTIFIERS\n")
            f.write("=" * 35 + "\n\n")
            for user in sorted_users:
                f.write(f"{user}\n")
        
        print(f"  💾 User identifiers saved to: user_identifiers.txt")
    else:
        print(f"  ❌ No user identifiers found")

def search_emails(text, output_dir):
    """Search for email addresses"""
    
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    emails = re.findall(email_pattern, text)
    
    if emails:
        unique_emails = sorted(set(emails))
        print(f"  📧 Found {len(unique_emails)} email addresses:")
        
        for email in unique_emails:
            print(f"    {email}")
        
        # Save email addresses
        email_file = os.path.join(output_dir, "email_addresses.txt")
        with open(email_file, 'w', encoding='utf-8') as f:
            f.write("EMAIL ADDRESSES FOUND\n")
            f.write("=" * 25 + "\n\n")
            for email in unique_emails:
                f.write(f"{email}\n")
        
        print(f"  💾 Email addresses saved to: email_addresses.txt")
    else:
        print(f"  ❌ No email addresses found")

def preview_content(text):
    """Show a preview of the decoded content"""
    
    lines = text.split('\n')
    non_empty_lines = [line.strip() for line in lines if line.strip()]
    
    print(f"  📊 Total lines: {len(lines):,}")
    print(f"  📊 Non-empty lines: {len(non_empty_lines):,}")
    print(f"  📊 Total characters: {len(text):,}")
    
    print(f"\n  📝 First 10 non-empty lines:")
    for i, line in enumerate(non_empty_lines[:10]):
        # Clean the line for display
        display_line = line.replace('\r', '').replace('\x00', '')
        if len(display_line) > 100:
            display_line = display_line[:100] + "..."
        print(f"    {i+1:2d}: {display_line}")

if __name__ == "__main__":
    ebcdic_cp500_decode()