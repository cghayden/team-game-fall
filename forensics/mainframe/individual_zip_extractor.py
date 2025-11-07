#!/usr/bin/env python3
"""
Individual ZIP File Extractor
Isolates and extracts each ZIP file from the NETDATA archive separately
"""

import os
import base64
import struct
import zipfile
import tempfile
from pathlib import Path

def extract_individual_zips():
    """Extract each ZIP file individually from the NETDATA archive"""
    
    file_path = "/Users/corey/team-game-fall/forensics/mainframe/ARCHIVE.NETDATA.XMI"
    
    print("📁 INDIVIDUAL ZIP FILE EXTRACTOR")
    print("=" * 50)
    
    # Decode base64 first
    with open(file_path, 'rb') as f:
        content = f.read()
    
    lines = content.split(b'\n')
    base64_content = b''.join(line.strip() for line in lines if line.strip())
    decoded = base64.b64decode(base64_content)
    
    print(f"📊 Decoded {len(decoded):,} bytes from base64")
    
    # Create output directory
    output_dir = "/tmp/individual_zips"
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    # ZIP file positions we identified earlier
    zip_entries = [
        (211, "EMAILS"),
        (1244, "Q1"), 
        (5282, "Q2"),
        (8772, "Q3"),
        (12196, "Q4"),
        (16153, "USERS")
    ]
    
    print(f"\n📦 Processing {len(zip_entries)} ZIP entries...")
    
    for i, (start_pos, name) in enumerate(zip_entries):
        print(f"\n📁 Processing {name} (Entry {i+1})...")
        
        # Calculate end position (start of next entry or end of data)
        if i < len(zip_entries) - 1:
            end_pos = zip_entries[i + 1][0]  # Start of next entry
        else:
            end_pos = len(decoded)  # End of data
        
        # Extract this ZIP segment
        zip_data = decoded[start_pos:end_pos]
        
        print(f"  📏 Extracted {len(zip_data):,} bytes from position {start_pos} to {end_pos}")
        
        # Try multiple extraction methods
        extract_zip_segment(zip_data, name, output_dir, start_pos)
    
    print(f"\n✅ Individual ZIP extraction complete!")
    print(f"📂 Results saved to: {output_dir}")

def extract_zip_segment(data, name, output_dir, original_pos):
    """Try multiple methods to extract a ZIP segment"""
    
    # Method 1: Try as complete ZIP file
    success = try_complete_zip(data, name, output_dir)
    
    if not success:
        # Method 2: Try to find ZIP boundaries more precisely
        success = try_precise_zip_boundaries(data, name, output_dir, original_pos)
    
    if not success:
        # Method 3: Try to reconstruct ZIP with proper central directory
        success = try_reconstruct_zip(data, name, output_dir)
    
    if not success:
        # Method 4: Extract raw compressed data and try manual decompression
        extract_raw_compressed_data(data, name, output_dir)

def try_complete_zip(data, name, output_dir):
    """Try to extract as a complete ZIP file"""
    
    print(f"    🔧 Method 1: Complete ZIP extraction...")
    
    try:
        # Save as ZIP file
        zip_path = os.path.join(output_dir, f"{name}_complete.zip")
        with open(zip_path, 'wb') as f:
            f.write(data)
        
        # Try to open and extract
        extract_dir = os.path.join(output_dir, f"{name}_extracted")
        Path(extract_dir).mkdir(parents=True, exist_ok=True)
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            print(f"    ✅ Successfully opened {name} as ZIP file!")
            
            # List contents
            file_list = zip_ref.namelist()
            print(f"    📋 Contains {len(file_list)} files:")
            for file_name in file_list:
                info = zip_ref.getinfo(file_name)
                print(f"      📄 {file_name} - {info.file_size:,} bytes")
            
            # Extract all files
            zip_ref.extractall(extract_dir)
            
            # Analyze extracted files
            analyze_extracted_files(extract_dir, name)
            
            return True
    
    except Exception as e:
        print(f"    ❌ Complete ZIP failed: {e}")
        return False

def try_precise_zip_boundaries(data, name, output_dir, original_pos):
    """Try to find precise ZIP boundaries"""
    
    print(f"    🔧 Method 2: Precise boundary detection...")
    
    try:
        # Look for end of central directory signature
        eocd_sig = b'PK\x05\x06'
        eocd_pos = data.find(eocd_sig)
        
        if eocd_pos != -1:
            print(f"    📍 Found EOCD at position {eocd_pos}")
            
            # Read EOCD record to find actual end
            if eocd_pos + 22 <= len(data):
                eocd_data = data[eocd_pos:eocd_pos + 22]
                
                # Parse EOCD (last 2 bytes are comment length)
                comment_len = struct.unpack('<H', eocd_data[20:22])[0]
                actual_end = eocd_pos + 22 + comment_len
                
                print(f"    📏 Calculated actual end: {actual_end}")
                
                # Extract precise ZIP data
                precise_data = data[:actual_end]
                
                zip_path = os.path.join(output_dir, f"{name}_precise.zip")
                with open(zip_path, 'wb') as f:
                    f.write(precise_data)
                
                # Try to extract
                extract_dir = os.path.join(output_dir, f"{name}_precise_extracted")
                Path(extract_dir).mkdir(parents=True, exist_ok=True)
                
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    print(f"    ✅ Precise boundary extraction successful!")
                    zip_ref.extractall(extract_dir)
                    analyze_extracted_files(extract_dir, name)
                    return True
    
    except Exception as e:
        print(f"    ❌ Precise boundary failed: {e}")
    
    return False

def try_reconstruct_zip(data, name, output_dir):
    """Try to reconstruct ZIP with proper structure"""
    
    print(f"    🔧 Method 3: ZIP reconstruction...")
    
    try:
        # Find local file header
        if not data.startswith(b'PK\x03\x04'):
            print(f"    ❌ No local file header found")
            return False
        
        # Parse local file header
        header = data[:30]
        sig, ver, flags, method, time, date, crc, comp_size, uncomp_size, name_len, extra_len = struct.unpack('<LHHHHHLLLHH', header)
        
        # Extract filename
        filename = data[30:30 + name_len].decode('utf-8', errors='replace')
        
        # Extract file data
        file_data_start = 30 + name_len + extra_len
        file_data_end = file_data_start + comp_size
        
        if file_data_end <= len(data):
            file_data = data[file_data_start:file_data_end]
            
            print(f"    📄 Found file: {filename}")
            print(f"    📏 Method: {method}, Compressed: {comp_size}, Uncompressed: {uncomp_size}")
            
            # Try to create a proper ZIP file with central directory
            reconstruct_path = os.path.join(output_dir, f"{name}_reconstructed.zip")
            
            # For now, save the raw file data
            raw_file_path = os.path.join(output_dir, f"{name}_{filename}_raw.bin")
            with open(raw_file_path, 'wb') as f:
                f.write(file_data)
            
            print(f"    💾 Raw file data saved: {name}_{filename}_raw.bin")
            
            # Try to decompress if it's deflated
            if method == 8:  # Deflate
                decompress_deflate_data(file_data, filename, name, output_dir)
            
            return True
    
    except Exception as e:
        print(f"    ❌ ZIP reconstruction failed: {e}")
    
    return False

def extract_raw_compressed_data(data, name, output_dir):
    """Extract and analyze raw compressed data"""
    
    print(f"    🔧 Method 4: Raw data extraction...")
    
    try:
        # Save raw segment
        raw_path = os.path.join(output_dir, f"{name}_raw_segment.bin")
        with open(raw_path, 'wb') as f:
            f.write(data)
        
        print(f"    💾 Raw segment saved: {name}_raw_segment.bin")
        
        # Try to find readable content
        readable_content = extract_readable_content(data)
        if readable_content:
            readable_path = os.path.join(output_dir, f"{name}_readable.txt")
            with open(readable_path, 'w', encoding='utf-8') as f:
                f.write(readable_content)
            print(f"    📝 Readable content saved: {name}_readable.txt")
        
        # Look for specific patterns
        search_patterns_in_data(data, name)
        
    except Exception as e:
        print(f"    ❌ Raw extraction failed: {e}")

def decompress_deflate_data(compressed_data, filename, zip_name, output_dir):
    """Try various deflate decompression methods"""
    
    print(f"      🗜️  Trying deflate decompression...")
    
    import zlib
    
    methods = [
        ("Standard deflate", lambda d: zlib.decompress(d, -15)),
        ("Deflate with header", lambda d: zlib.decompress(d)),
        ("Raw deflate", lambda d: zlib.decompress(d, -zlib.MAX_WBITS)),
        ("Skip 2 bytes", lambda d: zlib.decompress(d[2:], -15)),
        ("Skip 4 bytes", lambda d: zlib.decompress(d[4:], -15)),
    ]
    
    for desc, func in methods:
        try:
            decompressed = func(compressed_data)
            print(f"      ✅ {desc} successful: {len(decompressed):,} bytes")
            
            # Save decompressed data
            decomp_path = os.path.join(output_dir, f"{zip_name}_{filename}_decompressed.txt")
            
            # Try to save as text
            try:
                text = decompressed.decode('utf-8')
                with open(decomp_path, 'w', encoding='utf-8') as f:
                    f.write(text)
                print(f"      📝 Decompressed text saved: {zip_name}_{filename}_decompressed.txt")
                
                # Search for FIRE/VIPER in decompressed content
                search_patterns_in_text(text, zip_name, filename)
                
            except UnicodeDecodeError:
                # Save as binary
                with open(decomp_path + '.bin', 'wb') as f:
                    f.write(decompressed)
                print(f"      📄 Decompressed binary saved: {zip_name}_{filename}_decompressed.txt.bin")
            
            return True
        
        except Exception as e:
            print(f"      ❌ {desc} failed: {e}")
    
    return False

def extract_readable_content(data):
    """Extract readable ASCII content from binary data"""
    
    readable_chars = []
    current_sequence = []
    
    for byte in data:
        if 32 <= byte <= 126 or byte in [9, 10, 13]:  # Printable + whitespace
            current_sequence.append(chr(byte))
        else:
            if len(current_sequence) >= 5:  # Save sequences of 5+ chars
                readable_chars.append(''.join(current_sequence))
            current_sequence = []
    
    # Don't forget the last sequence
    if len(current_sequence) >= 5:
        readable_chars.append(''.join(current_sequence))
    
    return '\n'.join(readable_chars) if readable_chars else None

def search_patterns_in_data(data, name):
    """Search for FIRE/VIPER patterns in binary data"""
    
    patterns = [b'FIRE', b'fire', b'VIPER', b'viper', b'VIPER1', b'viper1']
    
    for pattern in patterns:
        if pattern in data:
            positions = []
            start = 0
            while True:
                pos = data.find(pattern, start)
                if pos == -1:
                    break
                positions.append(pos)
                start = pos + 1
            
            if positions:
                print(f"      🔍 Found '{pattern.decode()}' in {name} at positions: {positions}")

def search_patterns_in_text(text, zip_name, filename):
    """Search for FIRE/VIPER patterns in text"""
    
    import re
    
    fire_matches = re.findall(r'FIRE\w*', text, re.IGNORECASE)
    viper_matches = re.findall(r'VIPER\w*', text, re.IGNORECASE)
    
    if fire_matches:
        print(f"      🔥 FIRE patterns in {zip_name}/{filename}: {fire_matches}")
    
    if viper_matches:
        print(f"      🐍 VIPER patterns in {zip_name}/{filename}: {viper_matches}")

def analyze_extracted_files(extract_dir, zip_name):
    """Analyze successfully extracted files"""
    
    print(f"    📊 Analyzing extracted files from {zip_name}...")
    
    for root, dirs, files in os.walk(extract_dir):
        for file in files:
            file_path = os.path.join(root, file)
            rel_path = os.path.relpath(file_path, extract_dir)
            
            try:
                with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                
                print(f"      📄 {rel_path}: {len(content):,} characters")
                
                # Search for patterns
                import re
                fire_matches = re.findall(r'FIRE\w*', content, re.IGNORECASE)
                viper_matches = re.findall(r'VIPER\w*', content, re.IGNORECASE)
                
                if fire_matches:
                    print(f"        🔥 FIRE patterns: {fire_matches}")
                
                if viper_matches:
                    print(f"        🐍 VIPER patterns: {viper_matches}")
                
                # Show preview
                lines = content.split('\n')[:5]
                for i, line in enumerate(lines):
                    if line.strip():
                        clean_line = line.strip()[:100]
                        print(f"        {i+1}: {clean_line}{'...' if len(line.strip()) > 100 else ''}")
            
            except Exception as e:
                print(f"      ❌ Error reading {rel_path}: {e}")

if __name__ == "__main__":
    extract_individual_zips()