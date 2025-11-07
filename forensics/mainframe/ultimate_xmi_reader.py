#!/usr/bin/env python3
"""
Ultimate XMI Archive Reader
Final comprehensive script to read ARCHIVE.NETDATA.XMI using all available methods
"""

import os
import base64
import struct
from pathlib import Path

def ultimate_xmi_reader():
    """Ultimate comprehensive XMI archive reader"""
    
    file_path = "/Users/corey/team-game-fall/forensics/mainframe/ARCHIVE.NETDATA.XMI"
    
    print("🔍 ULTIMATE XMI ARCHIVE READER")
    print("=" * 50)
    
    # Step 1: Basic file info
    print("📊 BASIC FILE INFORMATION")
    print("-" * 30)
    
    with open(file_path, 'rb') as f:
        content = f.read()
    
    print(f"Original file size: {len(content):,} bytes")
    
    # Step 2: Decode base64
    print(f"\n🔓 BASE64 DECODING")
    print("-" * 30)
    
    lines = content.split(b'\n')
    base64_content = b''.join(line.strip() for line in lines if line.strip())
    decoded = base64.b64decode(base64_content)
    
    print(f"Decoded size: {len(decoded):,} bytes")
    
    # Save decoded content for analysis
    decoded_path = "/tmp/xmi_decoded_complete.bin"
    with open(decoded_path, 'wb') as f:
        f.write(decoded)
    print(f"Decoded data saved to: {decoded_path}")
    
    # Step 3: Analyze structure
    print(f"\n📁 ZIP STRUCTURE ANALYSIS")
    print("-" * 30)
    
    # Find all ZIP signatures
    zip_entries = find_zip_entries(decoded)
    
    # Step 4: Extract readable content directly
    print(f"\n📖 DIRECT CONTENT EXTRACTION")
    print("-" * 30)
    
    output_dir = "/tmp/xmi_ultimate_extraction"
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    # Try to extract content using different methods
    for i, entry in enumerate(zip_entries):
        extract_entry_content(decoded, entry, output_dir, i+1)
    
    # Step 5: Look for readable strings in the entire decoded content
    print(f"\n🔎 STRING ANALYSIS")
    print("-" * 30)
    
    extract_readable_strings(decoded, output_dir)
    
    print(f"\n✅ Analysis complete! Check {output_dir} for extracted files")

def find_zip_entries(data):
    """Find all ZIP local file headers"""
    
    entries = []
    pos = 0
    
    while True:
        pos = data.find(b'PK\x03\x04', pos)
        if pos == -1:
            break
        
        if pos + 30 <= len(data):
            header = data[pos:pos + 30]
            try:
                sig, ver, flags, method, time, date, crc, comp_size, uncomp_size, name_len, extra_len = struct.unpack('<LHHHHHLLLHH', header)
                
                # Extract filename if possible
                name_start = pos + 30
                name_end = name_start + name_len
                
                filename = "unknown"
                if name_end <= len(data):
                    filename = data[name_start:name_end].decode('utf-8', errors='replace')
                
                entries.append({
                    'position': pos,
                    'filename': filename,
                    'method': method,
                    'compressed_size': comp_size,
                    'uncompressed_size': uncomp_size,
                    'name_len': name_len,
                    'extra_len': extra_len
                })
                
                print(f"  Entry: {filename} at pos {pos} (method {method}, {comp_size}→{uncomp_size} bytes)")
                
            except:
                pass
        
        pos += 4
    
    return entries

def extract_entry_content(data, entry, output_dir, entry_num):
    """Extract content from a ZIP entry using multiple strategies"""
    
    pos = entry['position']
    filename = entry['filename']
    comp_size = entry['compressed_size']
    name_len = entry['name_len']
    extra_len = entry['extra_len']
    
    print(f"\n📦 Extracting {filename} (Entry {entry_num})")
    
    # Calculate data positions
    data_start = pos + 30 + name_len + extra_len
    data_end = data_start + comp_size
    
    if data_end > len(data):
        print(f"  ❌ Data extends beyond file bounds")
        return
    
    compressed_data = data[data_start:data_end]
    
    # Strategy 1: Try standard decompression methods
    decompressed = try_decompress_all_methods(compressed_data)
    
    if decompressed:
        # Save decompressed content
        safe_filename = filename.replace('/', '_').replace('\\', '_')
        output_path = os.path.join(output_dir, safe_filename)
        
        with open(output_path, 'wb') as f:
            f.write(decompressed)
        
        print(f"  ✅ Decompressed and saved: {safe_filename}")
        analyze_content(decompressed, filename)
    else:
        # Strategy 2: Look for readable content in compressed data
        print(f"  ⚠️  Decompression failed, searching for readable content...")
        readable_content = extract_readable_from_bytes(compressed_data)
        
        if readable_content:
            safe_filename = f"{filename}_readable.txt"
            output_path = os.path.join(output_dir, safe_filename)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(readable_content)
            
            print(f"  📝 Saved readable content: {safe_filename}")
            print(f"      Preview: {readable_content[:100]}...")

def try_decompress_all_methods(data):
    """Try all possible decompression methods"""
    
    import zlib
    import gzip
    import bz2
    
    methods = [
        # Zlib methods
        (lambda d: zlib.decompress(d, -15), "Raw deflate"),
        (lambda d: zlib.decompress(d, 15), "Zlib deflate"),
        (lambda d: zlib.decompress(d[2:], -15), "Raw deflate (skip 2)"),
        (lambda d: zlib.decompress(d[4:], -15), "Raw deflate (skip 4)"),
        
        # Gzip methods
        (lambda d: gzip.decompress(d), "Gzip"),
        
        # Bzip2 methods
        (lambda d: bz2.decompress(d), "Bzip2"),
        
        # Try different window sizes
        (lambda d: zlib.decompress(d, -9), "Raw deflate (wbits -9)"),
        (lambda d: zlib.decompress(d, -12), "Raw deflate (wbits -12)"),
    ]
    
    for method_func, method_name in methods:
        try:
            result = method_func(data)
            print(f"    ✅ {method_name} successful: {len(result)} bytes")
            return result
        except Exception as e:
            continue
    
    return None

def extract_readable_from_bytes(data):
    """Extract readable strings from binary data"""
    
    import re
    
    # Try different encodings
    for encoding in ['utf-8', 'latin-1', 'cp1252', 'ascii']:
        try:
            text = data.decode(encoding, errors='ignore')
            
            # Find sequences of printable characters
            readable_parts = re.findall(r'[A-Za-z0-9\s\.,;:!?\-_(){}[\]@#+*=/\\]{10,}', text)
            
            if readable_parts:
                # Clean and join readable parts
                cleaned = []
                for part in readable_parts:
                    clean_part = ' '.join(part.split())  # Clean whitespace
                    if len(clean_part) > 15:  # Only keep substantial parts
                        cleaned.append(clean_part)
                
                if cleaned:
                    return '\n'.join(cleaned)
        
        except:
            continue
    
    return None

def extract_readable_strings(data, output_dir):
    """Extract all readable strings from the entire decoded content"""
    
    import re
    
    # Look for long sequences of readable text
    text_content = data.decode('utf-8', errors='ignore')
    
    # Find email addresses
    emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text_content)
    if emails:
        with open(os.path.join(output_dir, "extracted_emails.txt"), 'w') as f:
            f.write('\n'.join(sorted(set(emails))))
        print(f"  📧 Found {len(set(emails))} unique email addresses")
    
    # Find readable text blocks
    text_blocks = re.findall(r'[A-Za-z][A-Za-z0-9\s\.,;:!?\-_(){}[\]]{50,}', text_content)
    if text_blocks:
        with open(os.path.join(output_dir, "extracted_text_blocks.txt"), 'w') as f:
            for i, block in enumerate(text_blocks):
                clean_block = ' '.join(block.split())
                f.write(f"Block {i+1}:\n{clean_block}\n\n")
        print(f"  📄 Found {len(text_blocks)} readable text blocks")
    
    # Find potential usernames/identifiers
    identifiers = re.findall(r'\b[a-zA-Z][a-zA-Z0-9._-]{2,15}\b', text_content)
    if identifiers:
        unique_ids = sorted(set(identifiers))
        with open(os.path.join(output_dir, "extracted_identifiers.txt"), 'w') as f:
            f.write('\n'.join(unique_ids))
        print(f"  🆔 Found {len(unique_ids)} potential identifiers")

def analyze_content(data, filename):
    """Analyze extracted content"""
    
    try:
        text = data.decode('utf-8')
        lines = [line.strip() for line in text.split('\n') if line.strip()]
        
        print(f"      Content: {len(lines)} lines")
        
        if lines:
            print(f"      First line: {lines[0][:50]}{'...' if len(lines[0]) > 50 else ''}")
            
            if filename.upper() == 'EMAILS':
                import re
                emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)
                print(f"      Contains {len(emails)} email addresses")
    
    except:
        print(f"      Binary content: {data[:20].hex()}...")

if __name__ == "__main__":
    ultimate_xmi_reader()