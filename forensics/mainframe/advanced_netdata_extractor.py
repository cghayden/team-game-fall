#!/usr/bin/env python3
"""
Advanced NETDATA ZIP Extractor
Attempts to extract individual files from the NETDATA archive using multiple methods
"""

import os
import base64
import struct
import zlib
import gzip
from pathlib import Path

def advanced_extraction():
    """Try advanced extraction methods"""
    
    file_path = "/Users/corey/team-game-fall/forensics/mainframe/ARCHIVE.NETDATA.XMI"
    
    print("🔧 ADVANCED NETDATA ZIP EXTRACTOR")
    print("=" * 50)
    
    # Decode base64
    with open(file_path, 'rb') as f:
        content = f.read()
    
    lines = content.split(b'\n')
    base64_content = b''.join(line.strip() for line in lines if line.strip())
    decoded = base64.b64decode(base64_content)
    
    print(f"📊 Decoded {len(decoded):,} bytes")
    
    # Try to extract each ZIP entry with different methods
    entries = [
        (211, "EMAILS", 989, 5520),
        (1244, "Q1", 3976, 21120),
        (5282, "Q2", 3430, 18160),
        (8772, "Q3", 3364, 17760),
        (12196, "Q4", 3895, 20640),
        (16153, "USERS", 231, 800)
    ]
    
    output_dir = "/tmp/advanced_extraction"
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    for pos, name, comp_size, uncomp_size in entries:
        print(f"\n📁 Processing {name}...")
        extract_with_multiple_methods(decoded, pos, name, comp_size, uncomp_size, output_dir)
    
    print(f"\n✅ Extraction complete. Check {output_dir} for results")

def extract_with_multiple_methods(data, pos, name, comp_size, uncomp_size, output_dir):
    """Try multiple extraction methods for a single entry"""
    
    try:
        # Parse ZIP local file header
        if pos + 30 > len(data):
            print(f"  ❌ Header position out of bounds")
            return
        
        header = data[pos:pos + 30]
        sig, ver, flags, method, time, date, crc, comp_size_hdr, uncomp_size_hdr, name_len, extra_len = struct.unpack('<LHHHHHLLLHH', header)
        
        # Extract filename
        name_start = pos + 30
        name_end = name_start + name_len
        filename = data[name_start:name_end].decode('utf-8', errors='replace')
        
        # Extract compressed data
        data_start = name_end + extra_len
        data_end = data_start + comp_size_hdr
        compressed_data = data[data_start:data_end]
        
        print(f"  📋 File: {filename}, Method: {method}, Size: {len(compressed_data)} bytes")
        
        # Method 1: Try standard decompression methods
        decompressed = try_standard_decompression(compressed_data, method, name)
        
        # Method 2: If that fails, try raw data analysis
        if not decompressed:
            decompressed = analyze_raw_compressed_data(compressed_data, name, output_dir)
        
        # Method 3: Try EBCDIC decoding of compressed data
        if not decompressed:
            decompressed = try_ebcdic_decode(compressed_data, name, output_dir)
        
        # Save any successful result
        if decompressed:
            output_path = os.path.join(output_dir, f"{filename}_decompressed.txt")
            with open(output_path, 'wb') as f:
                f.write(decompressed)
            print(f"  ✅ Saved decompressed data to: {filename}_decompressed.txt")
            
            # Analyze the decompressed content
            analyze_decompressed_content(decompressed, filename, output_dir)
        
        # Always save raw compressed data for manual analysis
        raw_path = os.path.join(output_dir, f"{filename}_raw.bin")
        with open(raw_path, 'wb') as f:
            f.write(compressed_data)
        
    except Exception as e:
        print(f"  ❌ Error processing {name}: {e}")

def try_standard_decompression(data, method, name):
    """Try standard decompression methods"""
    
    if method == 8:  # Deflate
        # Try various deflate methods
        methods_to_try = [
            ("Standard deflate", lambda d: zlib.decompress(d, -15)),
            ("Deflate with header", lambda d: zlib.decompress(d, 15)),
            ("Raw inflate", lambda d: zlib.decompress(d, -zlib.MAX_WBITS)),
            ("Skip 2 bytes", lambda d: zlib.decompress(d[2:], -15)),
            ("Skip 4 bytes", lambda d: zlib.decompress(d[4:], -15)),
        ]
        
        for desc, func in methods_to_try:
            try:
                result = func(data)
                print(f"    ✅ {desc} successful: {len(result)} bytes")
                return result
            except Exception as e:
                print(f"    ❌ {desc} failed: {e}")
        
    elif method == 0:  # No compression
        print(f"    ✅ No compression - returning raw data")
        return data
    
    return None

def analyze_raw_compressed_data(data, name, output_dir):
    """Analyze raw compressed data for readable content"""
    
    print(f"    🔍 Analyzing raw compressed data...")
    
    # Look for readable ASCII content
    readable_chars = []
    for byte in data:
        if 32 <= byte <= 126:  # Printable ASCII
            readable_chars.append(chr(byte))
        elif byte in [9, 10, 13]:  # Tab, LF, CR
            readable_chars.append(chr(byte))
        else:
            readable_chars.append('.')
    
    readable_text = ''.join(readable_chars)
    
    # Look for sequences of readable characters
    import re
    readable_sequences = re.findall(r'[A-Za-z0-9@._-]{5,}', readable_text)
    
    if readable_sequences:
        print(f"    📝 Found {len(readable_sequences)} readable sequences:")
        for seq in readable_sequences[:10]:
            print(f"      {seq}")
        
        # Save readable sequences
        readable_path = os.path.join(output_dir, f"{name}_readable_sequences.txt")
        with open(readable_path, 'w') as f:
            f.write(f"Readable sequences from {name}:\n")
            f.write("=" * 40 + "\n\n")
            for seq in readable_sequences:
                f.write(f"{seq}\n")
        
        # Check for FIRE or VIPER in readable sequences
        fire_matches = [seq for seq in readable_sequences if 'FIRE' in seq.upper()]
        viper_matches = [seq for seq in readable_sequences if 'VIPER' in seq.upper()]
        
        if fire_matches:
            print(f"    🔥 FIRE matches: {fire_matches}")
        if viper_matches:
            print(f"    🐍 VIPER matches: {viper_matches}")
    
    return None

def try_ebcdic_decode(data, name, output_dir):
    """Try EBCDIC decoding of the compressed data"""
    
    print(f"    🔤 Trying EBCDIC decode of compressed data...")
    
    ebcdic_codepages = ['cp037', 'cp500', 'cp875', 'cp1026', 'cp1140']
    
    for cp in ebcdic_codepages:
        try:
            decoded_text = data.decode(cp, errors='replace')
            
            # Look for meaningful content
            lines = [line.strip() for line in decoded_text.split('\n') if line.strip()]
            meaningful_lines = [line for line in lines if len(line) > 5 and any(c.isalpha() for c in line)]
            
            if meaningful_lines:
                print(f"    ✅ {cp} decode found meaningful content: {len(meaningful_lines)} lines")
                
                # Save EBCDIC decoded content
                ebcdic_path = os.path.join(output_dir, f"{name}_ebcdic_{cp}.txt")
                with open(ebcdic_path, 'w', encoding='utf-8') as f:
                    f.write(f"EBCDIC {cp} decode of {name}:\n")
                    f.write("=" * 40 + "\n\n")
                    f.write(decoded_text)
                
                # Search for FIRE and VIPER
                text_upper = decoded_text.upper()
                if 'FIRE' in text_upper:
                    print(f"    🔥 Found 'FIRE' in {cp} decoded text!")
                if 'VIPER' in text_upper:
                    print(f"    🐍 Found 'VIPER' in {cp} decoded text!")
                
                return decoded_text.encode('utf-8')
        
        except Exception as e:
            continue
    
    print(f"    ❌ No successful EBCDIC decode")
    return None

def analyze_decompressed_content(data, filename, output_dir):
    """Analyze successfully decompressed content"""
    
    print(f"    📊 Analyzing decompressed {filename}...")
    
    try:
        # Try to decode as text
        text = data.decode('utf-8', errors='replace')
        
        # Look for FIRE and VIPER patterns
        import re
        
        fire_matches = re.findall(r'FIRE\w*', text, re.IGNORECASE)
        viper_matches = re.findall(r'VIPER\w*', text, re.IGNORECASE)
        
        if fire_matches:
            print(f"    🔥 FIRE patterns found: {fire_matches}")
        
        if viper_matches:
            print(f"    🐍 VIPER patterns found: {viper_matches}")
        
        # Look for email addresses
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)
        if emails:
            print(f"    📧 Email addresses: {emails}")
        
        # Look for user IDs (typical mainframe pattern)
        user_ids = re.findall(r'\b[A-Z][A-Z0-9]{2,7}\b', text)
        if user_ids:
            print(f"    👤 Potential user IDs: {user_ids[:10]}")
        
    except UnicodeDecodeError:
        print(f"    📊 Binary content: {len(data)} bytes")
        # Look for patterns in binary data
        if b'FIRE' in data:
            print(f"    🔥 Found 'FIRE' in binary data!")
        if b'VIPER' in data:
            print(f"    🐍 Found 'VIPER' in binary data!")

if __name__ == "__main__":
    advanced_extraction()