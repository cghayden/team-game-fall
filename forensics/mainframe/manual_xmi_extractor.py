#!/usr/bin/env python3
"""
Manual ZIP Entry Extractor for XMI Archive
Manually extracts each ZIP entry since the archive appears to have format issues
"""

import os
import base64
import struct
import zlib
from pathlib import Path

def manual_extract():
    """Manually extract ZIP entries"""
    
    file_path = "/Users/corey/team-game-fall/forensics/mainframe/ARCHIVE.NETDATA.XMI"
    
    print("MANUAL XMI ZIP EXTRACTOR")
    print("=" * 40)
    
    # Decode the file
    with open(file_path, 'rb') as f:
        content = f.read()
    
    lines = content.split(b'\n')
    base64_content = b''.join(line.strip() for line in lines if line.strip())
    decoded = base64.b64decode(base64_content)
    
    print(f"Decoded {len(decoded):,} bytes")
    
    # Create output directory
    output_dir = "/tmp/xmi_manual_extraction"
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    # Known entry positions from previous analysis
    entries = [
        (211, "EMAILS", 989, 5520),
        (1244, "Q1", 3976, 21120),
        (5282, "Q2", None, None),  # Will parse from header
        (8772, "Q3", 3364, 17760),
        (12196, "Q4", 3895, 20640),
        (16153, "USERS", 231, 800)
    ]
    
    for pos, name, comp_size, uncomp_size in entries:
        print(f"\nProcessing {name} at position {pos}...")
        extract_single_entry(decoded, pos, name, output_dir)
    
    print(f"\nExtraction complete. Files saved to: {output_dir}")
    
    # Analyze all extracted files
    print(f"\nFILE ANALYSIS:")
    print("=" * 40)
    
    for root, dirs, files in os.walk(output_dir):
        for file in sorted(files):
            if not file.endswith('_raw.bin'):  # Skip raw files
                file_path = os.path.join(root, file)
                if os.path.getsize(file_path) > 0:
                    analyze_extracted_file(file_path)

def extract_single_entry(data, pos, expected_name, output_dir):
    """Extract a single ZIP entry manually"""
    
    try:
        # Parse local file header
        if pos + 30 > len(data):
            print(f"  Error: Not enough data for header at position {pos}")
            return
        
        header = data[pos:pos + 30]
        
        # Unpack local file header
        sig, ver, flags, method, time, date, crc, comp_size, uncomp_size, name_len, extra_len = struct.unpack('<LHHHHHLLLHH', header)
        
        print(f"  Signature: 0x{sig:08x}")
        
        if sig != 0x04034b50:  # PK\x03\x04
            print(f"  Invalid ZIP signature!")
            return
        
        # Extract filename
        name_start = pos + 30
        name_end = name_start + name_len
        
        if name_end > len(data):
            print(f"  Error: Filename extends beyond data")
            return
        
        filename = data[name_start:name_end].decode('utf-8', errors='replace')
        print(f"  Filename: '{filename}'")
        print(f"  Method: {method}, Compressed: {comp_size}, Uncompressed: {uncomp_size}")
        
        # Extract compressed data
        data_start = name_end + extra_len
        data_end = data_start + comp_size
        
        if data_end > len(data):
            print(f"  Error: Compressed data extends beyond available data")
            return
        
        compressed_data = data[data_start:data_end]
        print(f"  Extracted {len(compressed_data)} bytes of compressed data")
        
        # Save raw compressed data
        raw_filename = f"{filename}_raw.bin"
        raw_path = os.path.join(output_dir, raw_filename)
        with open(raw_path, 'wb') as f:
            f.write(compressed_data)
        
        # Try to decompress
        if method == 8:  # Deflate compression
            decompressed_data = try_decompress_deflate(compressed_data)
            
            if decompressed_data:
                # Save decompressed data
                output_path = os.path.join(output_dir, filename)
                with open(output_path, 'wb') as f:
                    f.write(decompressed_data)
                print(f"  Successfully decompressed and saved: {filename}")
                
                # Quick preview
                try:
                    preview = decompressed_data[:200].decode('utf-8', errors='replace')
                    print(f"  Preview: {preview[:100]}{'...' if len(preview) > 100 else ''}")
                except:
                    print(f"  Binary data: {decompressed_data[:20].hex()}...")
            else:
                print(f"  Failed to decompress {filename}")
        
        elif method == 0:  # No compression
            output_path = os.path.join(output_dir, filename)
            with open(output_path, 'wb') as f:
                f.write(compressed_data)
            print(f"  Saved uncompressed: {filename}")
    
    except Exception as e:
        print(f"  Error extracting {expected_name}: {e}")

def try_decompress_deflate(data):
    """Try various methods to decompress deflate data"""
    
    # Method 1: Standard deflate
    methods = [
        (zlib.decompress, (data, -15), "Standard deflate"),
        (zlib.decompress, (data, 15), "Deflate with header"),
        (zlib.decompress, (data[2:], -15), "Skip 2 bytes deflate"),
        (zlib.decompress, (data[4:], -15), "Skip 4 bytes deflate"),
    ]
    
    for func, args, desc in methods:
        try:
            result = func(*args)
            print(f"    {desc} successful: {len(result)} bytes")
            return result
        except Exception as e:
            continue
    
    return None

def analyze_extracted_file(file_path):
    """Analyze extracted file content"""
    
    filename = os.path.basename(file_path)
    size = os.path.getsize(file_path)
    
    print(f"\n{filename} ({size:,} bytes)")
    print("-" * (len(filename) + 15))
    
    try:
        with open(file_path, 'rb') as f:
            raw_data = f.read()
        
        # Try to decode as text
        try:
            content = raw_data.decode('utf-8')
            lines = [line.strip() for line in content.split('\n') if line.strip()]
            
            print(f"Text file with {len(lines)} non-empty lines")
            
            # Show content
            for i, line in enumerate(lines[:15]):
                print(f"  {i+1:2d}: {line}")
            
            if len(lines) > 15:
                print(f"  ... and {len(lines) - 15} more lines")
            
            # Specific analysis based on filename
            if filename.upper() == 'EMAILS':
                import re
                emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', content)
                if emails:
                    print(f"\n  EMAIL ADDRESSES FOUND ({len(emails)}):")
                    for email in sorted(set(emails)):
                        print(f"    {email}")
            
            elif filename.upper() in ['Q1', 'Q2', 'Q3', 'Q4']:
                questions = [line for line in lines if '?' in line]
                if questions:
                    print(f"\n  QUESTIONS FOUND ({len(questions)}):")
                    for i, q in enumerate(questions[:5]):
                        print(f"    {i+1}: {q}")
                    if len(questions) > 5:
                        print(f"    ... and {len(questions) - 5} more")
            
            elif filename.upper() == 'USERS':
                print(f"\n  USER DATA:")
                # Look for patterns in user data
                import re
                words = re.findall(r'\b[a-zA-Z][a-zA-Z0-9._-]{2,}\b', content)
                if words:
                    unique_words = sorted(set(words))[:20]
                    print(f"    Potential usernames/identifiers: {unique_words}")
        
        except UnicodeDecodeError:
            print(f"Binary file")
            print(f"  First 50 bytes (hex): {raw_data[:50].hex()}")
    
    except Exception as e:
        print(f"Error analyzing {filename}: {e}")

if __name__ == "__main__":
    manual_extract()