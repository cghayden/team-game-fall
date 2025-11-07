#!/usr/bin/env python3
"""
Working XMI Archive Extractor
Extracts files from ARCHIVE.NETDATA.XMI
"""

import os
import base64
import zipfile
import tempfile
from pathlib import Path

def extract_archive():
    """Extract the archive properly"""
    
    file_path = "/Users/corey/team-game-fall/forensics/mainframe/ARCHIVE.NETDATA.XMI"
    
    print("XMI ARCHIVE EXTRACTOR")
    print("=" * 40)
    
    # Step 1: Read and decode base64
    with open(file_path, 'rb') as f:
        content = f.read()
    
    lines = content.split(b'\n')
    base64_content = b''.join(line.strip() for line in lines if line.strip())
    decoded = base64.b64decode(base64_content)
    
    print(f"Original size: {len(content):,} bytes")
    print(f"Decoded size: {len(decoded):,} bytes")
    
    # Step 2: Find ZIP content (starts at position 211)
    zip_start = 211
    zip_data = decoded[zip_start:]
    
    print(f"ZIP data starts at position {zip_start}")
    print(f"ZIP data size: {len(zip_data):,} bytes")
    
    # Step 3: Extract using zipfile
    output_dir = "/tmp/xmi_extracted_files"
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    try:
        # Create temporary file for ZIP data
        with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as temp_zip:
            temp_zip.write(zip_data)
            temp_zip_path = temp_zip.name
        
        # Extract the ZIP
        with zipfile.ZipFile(temp_zip_path, 'r') as zip_ref:
            print(f"\nZIP file contents:")
            for info in zip_ref.filelist:
                print(f"  {info.filename} - {info.file_size:,} bytes (compressed: {info.compress_size:,})")
            
            print(f"\nExtracting to: {output_dir}")
            zip_ref.extractall(output_dir)
        
        # Clean up temp file
        os.unlink(temp_zip_path)
        
        # Analyze extracted files
        print(f"\nEXTRACTED FILES ANALYSIS:")
        print("=" * 40)
        
        for root, dirs, files in os.walk(output_dir):
            for file in sorted(files):
                file_path = os.path.join(root, file)
                analyze_file(file_path)
        
        print(f"\nAll files successfully extracted to: {output_dir}")
        
    except Exception as e:
        print(f"Error extracting ZIP: {e}")

def analyze_file(file_path):
    """Analyze an extracted file"""
    filename = os.path.basename(file_path)
    size = os.path.getsize(file_path)
    
    print(f"\n{filename.upper()} ({size:,} bytes)")
    print("-" * 30)
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        
        lines = content.strip().split('\n')
        non_empty_lines = [line for line in lines if line.strip()]
        
        print(f"Text file with {len(non_empty_lines)} lines")
        
        # Show first few lines
        print("Content preview:")
        for i, line in enumerate(non_empty_lines[:10]):
            print(f"  {i+1:2d}: {line.strip()}")
        
        if len(non_empty_lines) > 10:
            print(f"  ... and {len(non_empty_lines) - 10} more lines")
        
        # Look for specific patterns
        if filename.upper() == 'EMAILS':
            analyze_emails(content)
        elif filename.upper().startswith('Q'):
            analyze_questions(content, filename)
        elif filename.upper() == 'USERS':
            analyze_users(content)
    
    except Exception as e:
        print(f"Error reading file: {e}")

def analyze_emails(content):
    """Analyze EMAILS file for email addresses"""
    import re
    
    emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', content)
    if emails:
        print(f"\nFound {len(emails)} email addresses:")
        for email in sorted(set(emails)):
            print(f"  {email}")
    
    # Look for other patterns
    domains = re.findall(r'@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', content)
    if domains:
        unique_domains = sorted(set(domains))
        print(f"\nDomains found: {unique_domains}")

def analyze_questions(content, filename):
    """Analyze question files"""
    lines = content.strip().split('\n')
    
    # Look for question patterns
    questions = [line for line in lines if '?' in line]
    if questions:
        print(f"\nQuestions found in {filename}:")
        for i, q in enumerate(questions[:5]):
            print(f"  {i+1}: {q.strip()}")
        if len(questions) > 5:
            print(f"  ... and {len(questions) - 5} more questions")

def analyze_users(content):
    """Analyze USERS file"""
    lines = content.strip().split('\n')
    
    print(f"\nUser entries analysis:")
    
    # Look for usernames, IDs, etc.
    import re
    
    # Look for patterns that might be usernames
    usernames = []
    for line in lines:
        # Simple heuristic for usernames
        words = line.split()
        for word in words:
            if len(word) >= 3 and word.isalnum():
                usernames.append(word)
    
    if usernames:
        unique_users = sorted(set(usernames))[:10]  # First 10 unique
        print(f"Potential usernames: {unique_users}")

if __name__ == "__main__":
    extract_archive()