#!/usr/bin/env python3
"""
Advanced Archive File Analyzer
This script analyzes the ARCHIVE.NETDATA.XMI file using multiple approaches
since it doesn't appear to be a standard XMI format.
"""

import os
import sys
import base64
import binascii
import zipfile
import gzip
import struct
from pathlib import Path


def analyze_file_structure(file_path):
    """Analyze the basic structure of the file"""
    print("FILE STRUCTURE ANALYSIS")
    print("=" * 50)

    # File size and basic info
    file_size = os.path.getsize(file_path)
    print(f"File size: {file_size:,} bytes")

    # Read file content
    with open(file_path, "rb") as f:
        content = f.read()

    # Check for magic bytes / file signatures
    print(f"First 32 bytes (hex): {content[:32].hex()}")
    print(f"First 32 bytes (ASCII): {content[:32].decode('ascii', errors='replace')}")

    # Check if it might be base64 encoded
    first_line = content.split(b"\n")[0] if b"\n" in content else content[:100]
    print(f"First line length: {len(first_line)}")
    print(f"First line: {first_line.decode('ascii', errors='replace')}")

    return content


def try_base64_decode(content):
    """Try to decode as base64"""
    print("\nBASE64 DECODE ATTEMPT")
    print("=" * 50)

    try:
        # Try to decode the content as base64
        lines = content.split(b"\n")
        base64_content = b"".join(line.strip() for line in lines if line.strip())

        print(f"Attempting to decode {len(base64_content)} bytes as base64...")
        decoded = base64.b64decode(base64_content)

        print(f"Successfully decoded! Size: {len(decoded)} bytes")
        print(f"First 32 bytes of decoded content (hex): {decoded[:32].hex()}")
        print(
            f"First 32 bytes of decoded content (ASCII): {decoded[:32].decode('ascii', errors='replace')}"
        )

        return decoded
    except Exception as e:
        print(f"Base64 decode failed: {e}")
        return None


def check_for_zip_content(content):
    """Check if the content contains ZIP data"""
    print("\nZIP CONTENT CHECK")
    print("=" * 50)

    # Look for ZIP file signatures
    zip_signatures = [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"]

    for sig in zip_signatures:
        pos = content.find(sig)
        if pos != -1:
            print(f"Found ZIP signature at position {pos}: {sig.hex()}")

            # Try to extract ZIP content starting from this position
            try:
                zip_content = content[pos:]

                # Write to temporary file and try to open as ZIP
                temp_zip_path = "/tmp/extracted_archive.zip"
                with open(temp_zip_path, "wb") as f:
                    f.write(zip_content)

                with zipfile.ZipFile(temp_zip_path, "r") as zip_ref:
                    print("Successfully opened as ZIP file!")
                    print("Contents:")
                    for name in zip_ref.namelist():
                        info = zip_ref.getinfo(name)
                        print(
                            f"  {name} - {info.file_size} bytes (compressed: {info.compress_size})"
                        )

                    return zip_ref, temp_zip_path

            except Exception as e:
                print(f"Failed to open as ZIP: {e}")

    print("No ZIP content found")
    return None, None


def extract_zip_contents(zip_ref, zip_path, extract_dir):
    """Extract ZIP contents"""
    print(f"\nEXTRACTING ZIP CONTENTS to {extract_dir}")
    print("=" * 50)

    Path(extract_dir).mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        zip_ref.extractall(extract_dir)

        print("Extracted files:")
        for root, dirs, files in os.walk(extract_dir):
            for file in files:
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, extract_dir)
                size = os.path.getsize(file_path)
                print(f"  {rel_path} - {size} bytes")

                # Try to read and preview the file
                try:
                    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                        preview = f.read(200)
                        print(
                            f"    Preview: {preview[:100]}{'...' if len(preview) > 100 else ''}"
                        )
                except:
                    try:
                        with open(file_path, "rb") as f:
                            preview = f.read(50)
                            print(f"    Binary preview (hex): {preview.hex()}")
                    except:
                        print(f"    Could not preview file")


def search_for_patterns(content):
    """Search for interesting patterns in the content"""
    print("\nPATTERN ANALYSIS")
    print("=" * 50)

    patterns = {
        "Email addresses": rb"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "URLs": rb"https?://[^\s]+",
        "File paths": rb"/[^\s\x00]+",
        "Dates": rb"\d{4}[-/]\d{2}[-/]\d{2}",
        "Numbers": rb"\b\d+\b",
    }

    import re

    for pattern_name, pattern in patterns.items():
        matches = re.findall(pattern, content)
        if matches:
            print(f"{pattern_name}: {len(matches)} matches")
            for match in matches[:5]:  # Show first 5 matches
                try:
                    print(f"  {match.decode('ascii', errors='replace')}")
                except:
                    print(f"  {match}")
            if len(matches) > 5:
                print(f"  ... and {len(matches) - 5} more")


def main():
    file_path = "/Users/corey/team-game-fall/forensics/mainframe/ARCHIVE.NETDATA.XMI"

    if not os.path.exists(file_path):
        print(f"Error: File {file_path} not found!")
        sys.exit(1)

    print(f"Analyzing file: {file_path}")
    print("=" * 70)

    # Step 1: Analyze file structure
    content = analyze_file_structure(file_path)

    # Step 2: Try base64 decoding
    decoded_content = try_base64_decode(content)

    # Step 3: Check for ZIP content in original or decoded content
    contents_to_check = [content]
    if decoded_content:
        contents_to_check.append(decoded_content)

    zip_found = False
    for i, check_content in enumerate(contents_to_check):
        print(f"\nChecking content #{i+1} for ZIP data...")
        zip_ref, zip_path = check_for_zip_content(check_content)
        if zip_ref:
            extract_dir = f"/tmp/archive_extracted_{i+1}"
            extract_zip_contents(zip_ref, zip_path, extract_dir)
            zip_found = True
            break

    # Step 4: Pattern analysis on decoded content if available
    analysis_content = decoded_content if decoded_content else content
    search_for_patterns(analysis_content)

    # Step 5: Summary
    print("\nSUMMARY")
    print("=" * 50)
    print(f"File appears to be: ", end="")
    if decoded_content:
        print("Base64 encoded data")
        if zip_found:
            print("  Contains ZIP archive with extracted files")
        else:
            print("  Not a ZIP archive")
    else:
        print("Binary or encoded data (not standard base64)")


if __name__ == "__main__":
    main()
