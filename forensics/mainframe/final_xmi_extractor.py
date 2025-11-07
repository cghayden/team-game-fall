#!/usr/bin/env python3
"""
Final XMI Archive Extractor
This script handles the specific format of the ARCHIVE.NETDATA.XMI file
and extracts the individual files properly.
"""

import os
import sys
import base64
import struct
import zlib
from pathlib import Path

def extract_xmi_archive():
    """Extract the XMI archive using manual ZIP parsing"""
    
    file_path = "/Users/corey/team-game-fall/forensics/mainframe/ARCHIVE.NETDATA.XMI"
    
    print("FINAL XMI ARCHIVE EXTRACTOR")
    print("=" * 50)
    
    # Read and decode the file
    with open(file_path, 'rb') as f:
        content = f.read()
    
    # Decode base64
    lines = content.split(b'\n')
    base64_content = b''.join(line.strip() for line in lines if line.strip())
    decoded = base64.b64decode(base64_content)
    
    print(f"Decoded {len(decoded):,} bytes")
    
    # Create output directory
    output_dir = "/tmp/xmi_final_extraction"
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    # Extract each ZIP entry manually
    entries = [
        (211, "EMAILS"),
        (1244, "Q1"), 
        (5282, "Q2"),
        (8772, "Q3"),
        (12196, "Q4"),
        (16153, "USERS")
    ]
    
    for pos, expected_name in entries:
        print(f"\nExtracting entry at position {pos}: {expected_name}")
        extract_entry(decoded, pos, expected_name, output_dir)
    
    print(f"\nAll files extracted to: {output_dir}")
    
    # List and analyze extracted files
    print("\nEXTRACTED FILES ANALYSIS:")
    print("=" * 50)
    
    for root, dirs, files in os.walk(output_dir):
        for file in sorted(files):
            file_path = os.path.join(root, file)
            analyze_extracted_file(file_path)

def extract_entry(data, pos, expected_name, output_dir):
    """Extract a single ZIP entry"""
    try:
        # Parse local file header (30 bytes)
        header = data[pos:pos + 30]
        if len(header) < 30:
            print(f"  Error: Not enough data for header")
            return
        
        signature, version, flags, method, mod_time, mod_date, crc32, comp_size, uncomp_size, name_len, extra_len = struct.unpack('<LHHHHHLLLHH', header)
        
        # Extract filename
        name_start = pos + 30
        name_end = name_start + name_len
        filename = data[name_start:name_end].decode('utf-8', errors='replace')
        
        print(f"  Filename: {filename}")
        print(f"  Compression method: {method}")
        print(f"  Compressed size: {comp_size:,}")
        print(f"  Uncompressed size: {uncomp_size:,}")
        
        # Extract compressed data
        data_start = name_end + extra_len
        data_end = data_start + comp_size
        compressed_data = data[data_start:data_end]
        
        print(f"  Extracted {len(compressed_data)} bytes of compressed data")
        
        # Save the raw compressed data first
        raw_path = os.path.join(output_dir, f"{filename}_compressed.bin")
        with open(raw_path, 'wb') as f:
            f.write(compressed_data)
        print(f"  Saved compressed data to: {raw_path}")
        
        # Try different decompression methods
        decompressed = None
        
        # Method 1: Standard deflate
        try:
            decompressed = zlib.decompress(compressed_data, -15)
            print(f"  Standard deflate successful: {len(decompressed)} bytes")
        except Exception as e:
            print(f"  Standard deflate failed: {e}")
        
        # Method 2: Try with different window bits
        if not decompressed:
            for wbits in [15, -15, 9, -9, 12, -12]:
                try:
                    decompressed = zlib.decompress(compressed_data, wbits)
                    print(f"  Deflate with wbits={wbits} successful: {len(decompressed)} bytes")
                    break
                except:
                    continue
        
        # Method 3: Try raw decompression with skipping initial bytes
        if not decompressed:
            for skip in [0, 1, 2, 4, 8]:
                try:
                    decompressed = zlib.decompress(compressed_data[skip:], -15)
                    print(f"  Deflate with skip={skip} successful: {len(decompressed)} bytes")
                    break
                except:
                    continue
        
        # If decompression worked, save the result
        if decompressed:
            output_path = os.path.join(output_dir, filename)
            with open(output_path, 'wb') as f:
                f.write(decompressed)
            print(f"  Decompressed file saved to: {output_path}")
            
            # Quick preview
            preview_data(decompressed, filename)
        else:
            print(f"  Could not decompress data for {filename}")
            
            # Try to extract readable content from compressed data
            try:
                readable = compressed_data.decode('utf-8', errors='ignore')
                readable_lines = [line for line in readable.split('\n') if line.strip() and len(line.strip()) > 5]
                if readable_lines:
                    print(f"  Some readable content in compressed data:")
                    for line in readable_lines[:3]:
                        print(f"    {line.strip()[:60]}{'...' if len(line.strip()) > 60 else ''}")
            except:
                pass
    
    except Exception as e:
        print(f"  Error extracting entry: {e}")

def preview_data(data, filename):
    """Preview the extracted data"""
    try:
        text = data.decode('utf-8', errors='replace')
        lines = text.split('\n')
        non_empty_lines = [line.strip() for line in lines if line.strip()]
        
        print(f"  Preview of {filename} ({len(non_empty_lines)} non-empty lines):")
        for i, line in enumerate(non_empty_lines[:3]):
            print(f"    {line[:80]}{'...' if len(line) > 80 else ''}")
        
        if len(non_empty_lines) > 3:
            print(f"    ... and {len(non_empty_lines) - 3} more lines")
    
    except:
        print(f"  Binary data preview for {filename}: {data[:40].hex()}...")

def analyze_extracted_file(file_path):
    """Analyze an extracted file in detail"""
    filename = os.path.basename(file_path)
    size = os.path.getsize(file_path)
    
    print(f"\n{filename} ({size:,} bytes)")
    print("-" * (len(filename) + 20))
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Try to decode as text
        try:
            text = data.decode('utf-8')
            lines = text.split('\n')
            non_empty_lines = [line.strip() for line in lines if line.strip()]
            
            print(f"Text file with {len(non_empty_lines)} non-empty lines")
            
            # Show structure
            if non_empty_lines:
                print("Content structure:")
                for i, line in enumerate(non_empty_lines[:10]):
                    print(f"  {i+1:2d}: {line[:100]}{'...' if len(line) > 100 else ''}")
                
                if len(non_empty_lines) > 10:
                    print(f"  ... and {len(non_empty_lines) - 10} more lines")
            
            # Look for patterns
            import re
            
            # Email patterns
            emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)
            if emails:
                print(f"Email addresses found: {len(emails)}")
                for email in emails[:5]:
                    print(f"  {email}")
                if len(emails) > 5:
                    print(f"  ... and {len(emails) - 5} more")
            
            # Date patterns
            dates = re.findall(r'\d{4}[-/]\d{2}[-/]\d{2}', text)
            if dates:
                print(f"Dates found: {set(dates)}")
            
            # Number patterns
            numbers = re.findall(r'\b\d+\b', text)
            if len(numbers) > 10:
                print(f"Numbers found: {len(numbers)} (showing unique values)")
                unique_numbers = sorted(set(int(n) for n in numbers if n.isdigit()))[:10]
                print(f"  Sample: {unique_numbers}")
        
        except UnicodeDecodeError:
            print("Binary file")
            print(f"First 100 bytes (hex): {data[:100].hex()}")
    
    except Exception as e:
        print(f"Error analyzing file: {e}")

if __name__ == "__main__":
    extract_xmi_archive()