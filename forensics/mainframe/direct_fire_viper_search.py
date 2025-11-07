#!/usr/bin/env python3
"""
Direct FIRE/VIPER Search in NETDATA
Search directly in the raw decoded data for FIRE and VIPER patterns
"""

import os
import base64
import re

def direct_search():
    """Direct search for FIRE and VIPER in all possible encodings"""
    
    file_path = "/Users/corey/team-game-fall/forensics/mainframe/ARCHIVE.NETDATA.XMI"
    
    print("🔍 DIRECT FIRE/VIPER SEARCH")
    print("=" * 40)
    
    # Decode base64
    with open(file_path, 'rb') as f:
        content = f.read()
    
    lines = content.split(b'\n')
    base64_content = b''.join(line.strip() for line in lines if line.strip())
    decoded = base64.b64decode(base64_content)
    
    print(f"📊 Searching in {len(decoded):,} bytes of decoded data")
    
    # Search 1: Binary search
    print(f"\n🔍 BINARY SEARCH")
    print("-" * 20)
    
    fire_binary = [b'FIRE', b'fire', b'Fire']
    viper_binary = [b'VIPER1', b'viper1', b'Viper1', b'VIPER', b'viper']
    
    for pattern in fire_binary:
        positions = find_all_positions(decoded, pattern)
        if positions:
            print(f"  🔥 Found '{pattern.decode()}' at positions: {positions}")
            show_context(decoded, positions, pattern)
    
    for pattern in viper_binary:
        positions = find_all_positions(decoded, pattern)
        if positions:
            print(f"  🐍 Found '{pattern.decode()}' at positions: {positions}")
            show_context(decoded, positions, pattern)
    
    # Search 2: EBCDIC search
    print(f"\n🔍 EBCDIC SEARCH")
    print("-" * 20)
    
    ebcdic_codepages = ['cp037', 'cp500', 'cp875', 'cp1140']
    
    for cp in ebcdic_codepages:
        try:
            ebcdic_text = decoded.decode(cp, errors='replace')
            
            # Search for FIRE patterns
            fire_matches = re.finditer(r'FIRE\w*', ebcdic_text, re.IGNORECASE)
            for match in fire_matches:
                print(f"  🔥 {cp}: FIRE pattern '{match.group()}' at position {match.start()}")
                show_text_context(ebcdic_text, match.start(), match.group())
            
            # Search for VIPER patterns  
            viper_matches = re.finditer(r'VIPER\w*', ebcdic_text, re.IGNORECASE)
            for match in viper_matches:
                print(f"  🐍 {cp}: VIPER pattern '{match.group()}' at position {match.start()}")
                show_text_context(ebcdic_text, match.start(), match.group())
        
        except Exception as e:
            print(f"  ❌ {cp} decode failed: {e}")
    
    # Search 3: ASCII search with error handling
    print(f"\n🔍 ASCII SEARCH")
    print("-" * 20)
    
    try:
        ascii_text = decoded.decode('ascii', errors='replace')
        
        fire_matches = list(re.finditer(r'FIRE\w*', ascii_text, re.IGNORECASE))
        viper_matches = list(re.finditer(r'VIPER\w*', ascii_text, re.IGNORECASE))
        
        if fire_matches:
            print(f"  🔥 ASCII: Found {len(fire_matches)} FIRE patterns")
            for match in fire_matches:
                print(f"    '{match.group()}' at position {match.start()}")
        
        if viper_matches:
            print(f"  🐍 ASCII: Found {len(viper_matches)} VIPER patterns") 
            for match in viper_matches:
                print(f"    '{match.group()}' at position {match.start()}")
        
        if not fire_matches and not viper_matches:
            print(f"  ❌ No FIRE or VIPER patterns found in ASCII")
    
    except Exception as e:
        print(f"  ❌ ASCII decode failed: {e}")
    
    # Search 4: Look for partial matches or similar patterns
    print(f"\n🔍 PARTIAL PATTERN SEARCH")
    print("-" * 30)
    
    # Look for FIR, FIRE fragments
    fir_positions = find_all_positions(decoded, b'FIR')
    if fir_positions:
        print(f"  🔥 Found 'FIR' fragments at: {fir_positions[:10]}{'...' if len(fir_positions) > 10 else ''}")
    
    # Look for VIP, VIPE fragments  
    vip_positions = find_all_positions(decoded, b'VIP')
    if vip_positions:
        print(f"  🐍 Found 'VIP' fragments at: {vip_positions[:10]}{'...' if len(vip_positions) > 10 else ''}")
    
    # Search 5: Search in individual ZIP entries
    print(f"\n🔍 ZIP ENTRY SEARCH")
    print("-" * 20)
    
    search_zip_entries(decoded)
    
    print(f"\n✅ Search complete")

def find_all_positions(data, pattern):
    """Find all positions of a pattern in data"""
    positions = []
    start = 0
    while True:
        pos = data.find(pattern, start)
        if pos == -1:
            break
        positions.append(pos)
        start = pos + 1
    return positions

def show_context(data, positions, pattern):
    """Show context around found patterns"""
    for pos in positions[:3]:  # Show first 3 matches
        start = max(0, pos - 50)
        end = min(len(data), pos + len(pattern) + 50)
        context = data[start:end]
        
        # Try to decode context as text
        try:
            context_text = context.decode('utf-8', errors='replace')
            print(f"    Context: ...{context_text}...")
        except:
            print(f"    Context (hex): {context.hex()}")

def show_text_context(text, pos, pattern):
    """Show text context around found patterns"""
    start = max(0, pos - 100)
    end = min(len(text), pos + len(pattern) + 100)
    context = text[start:end]
    print(f"    Context: ...{context}...")

def search_zip_entries(decoded):
    """Search within individual ZIP entries"""
    
    # Known ZIP entry positions
    entries = [
        (211, "EMAILS", 989),
        (1244, "Q1", 3976),
        (5282, "Q2", 3430),
        (8772, "Q3", 3364),
        (12196, "Q4", 3895),
        (16153, "USERS", 231)
    ]
    
    for pos, name, comp_size in entries:
        try:
            # Skip ZIP header to get to compressed data
            header_size = 30  # Basic header
            
            if pos + header_size < len(decoded):
                # Read filename length from header
                name_len = int.from_bytes(decoded[pos + 26:pos + 28], 'little')
                extra_len = int.from_bytes(decoded[pos + 28:pos + 30], 'little')
                
                data_start = pos + 30 + name_len + extra_len
                data_end = min(data_start + comp_size, len(decoded))
                
                if data_start < len(decoded):
                    entry_data = decoded[data_start:data_end]
                    
                    # Search for patterns in this entry
                    fire_found = b'FIRE' in entry_data or b'fire' in entry_data
                    viper_found = b'VIPER' in entry_data or b'viper' in entry_data
                    
                    if fire_found or viper_found:
                        print(f"  📁 {name}: ", end="")
                        if fire_found:
                            print(f"🔥 FIRE ", end="")
                        if viper_found:
                            print(f"🐍 VIPER ", end="")
                        print()
                    else:
                        print(f"  📁 {name}: No patterns found")
        
        except Exception as e:
            print(f"  📁 {name}: Error - {e}")

if __name__ == "__main__":
    direct_search()