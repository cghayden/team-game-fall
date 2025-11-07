#!/usr/bin/env python3
"""
XMI Archive Data Extractor
This script extracts and analyzes the decoded content from ARCHIVE.NETDATA.XMI
"""

import os
import sys
import base64
import zipfile
import struct
from pathlib import Path


def decode_and_extract():
    """Decode the base64 content and extract any embedded archives"""
    file_path = "/Users/corey/team-game-fall/forensics/mainframe/ARCHIVE.NETDATA.XMI"

    print("XMI ARCHIVE DATA EXTRACTOR")
    print("=" * 50)

    # Read and decode the file
    with open(file_path, "rb") as f:
        content = f.read()

    print(f"Original file size: {len(content):,} bytes")

    # Decode base64
    lines = content.split(b"\n")
    base64_content = b"".join(line.strip() for line in lines if line.strip())

    try:
        decoded = base64.b64decode(base64_content)
        print(f"Decoded size: {len(decoded):,} bytes")
    except Exception as e:
        print(f"Base64 decode error: {e}")
        return

    # Save decoded content
    decoded_path = "/tmp/archive_decoded.bin"
    with open(decoded_path, "wb") as f:
        f.write(decoded)
    print(f"Saved decoded content to: {decoded_path}")

    # Look for ZIP signatures and try to extract each one
    zip_signatures = [b"PK\x03\x04"]  # Local file header

    zip_count = 0
    pos = 0

    while True:
        # Find next ZIP signature
        zip_pos = decoded.find(b"PK\x03\x04", pos)
        if zip_pos == -1:
            break

        print(f"\nFound ZIP signature at position {zip_pos}")
        zip_count += 1

        # Try to find the end of this ZIP file
        # Look for end of central directory signature
        end_sig_pos = decoded.find(b"PK\x05\x06", zip_pos)

        if end_sig_pos != -1:
            # Find the actual end of the ZIP file
            # The end of central directory record is variable length
            # We need to read the comment length to find the true end
            try:
                # Skip to the comment length field (22 bytes from end signature + 20 bytes)
                comment_len_pos = end_sig_pos + 20
                if comment_len_pos + 2 <= len(decoded):
                    comment_len = struct.unpack(
                        "<H", decoded[comment_len_pos : comment_len_pos + 2]
                    )[0]
                    zip_end = comment_len_pos + 2 + comment_len
                else:
                    zip_end = end_sig_pos + 22  # Minimum size without comment

                print(f"  ZIP ends at position {zip_end}")

                # Extract this ZIP file
                zip_data = decoded[zip_pos:zip_end]

                # Save and try to open
                zip_file_path = f"/tmp/extracted_zip_{zip_count}.zip"
                with open(zip_file_path, "wb") as f:
                    f.write(zip_data)

                try:
                    extract_dir = f"/tmp/zip_contents_{zip_count}"
                    Path(extract_dir).mkdir(parents=True, exist_ok=True)

                    with zipfile.ZipFile(zip_file_path, "r") as zip_ref:
                        print(f"  Successfully opened ZIP file {zip_count}")
                        print(f"  Contents:")
                        for name in zip_ref.namelist():
                            info = zip_ref.getinfo(name)
                            print(f"    {name} - {info.file_size:,} bytes")

                        # Extract all files
                        zip_ref.extractall(extract_dir)
                        print(f"  Extracted to: {extract_dir}")

                        # Analyze extracted files
                        analyze_extracted_files(extract_dir)

                except Exception as e:
                    print(f"  Error processing ZIP {zip_count}: {e}")

                pos = zip_end
            except Exception as e:
                print(f"  Error finding ZIP end: {e}")
                pos = zip_pos + 4
        else:
            # No end signature found, try next occurrence
            pos = zip_pos + 4

    if zip_count == 0:
        print("\nNo valid ZIP files found. Analyzing raw decoded data...")
        analyze_raw_data(decoded)

    print(f"\nProcessing complete. Found and processed {zip_count} ZIP file(s).")


def analyze_extracted_files(extract_dir):
    """Analyze files extracted from ZIP"""
    print(f"\n    Analyzing extracted files:")

    for root, dirs, files in os.walk(extract_dir):
        for file in files:
            file_path = os.path.join(root, file)
            rel_path = os.path.relpath(file_path, extract_dir)
            size = os.path.getsize(file_path)

            print(f"      {rel_path} ({size:,} bytes)")

            # Try to read and analyze the file
            try:
                # Check if it's text
                with open(file_path, "rb") as f:
                    sample = f.read(1024)

                # Try to decode as text
                try:
                    text_sample = sample.decode("utf-8")
                    print(f"        Text content preview:")
                    lines = text_sample.split("\n")[:3]
                    for line in lines:
                        if line.strip():
                            print(
                                f"          {line.strip()[:80]}{'...' if len(line.strip()) > 80 else ''}"
                            )
                except UnicodeDecodeError:
                    # Binary file
                    print(f"        Binary content (hex): {sample[:40].hex()}...")

                    # Check for specific file types
                    if sample.startswith(b"\x89PNG"):
                        print(f"        -> PNG image file")
                    elif sample.startswith(b"\xff\xd8\xff"):
                        print(f"        -> JPEG image file")
                    elif sample.startswith(b"%PDF"):
                        print(f"        -> PDF file")
                    elif b"<html" in sample.lower() or b"<xml" in sample.lower():
                        print(f"        -> HTML/XML file")

            except Exception as e:
                print(f"        Error analyzing file: {e}")


def analyze_raw_data(data):
    """Analyze raw decoded data for interesting patterns"""
    print("Analyzing raw decoded data...")

    # Look for text patterns
    import re

    # Try to find readable text sections
    text_matches = re.findall(rb"[A-Za-z0-9\s]{20,}", data)
    if text_matches:
        print(f"\nFound {len(text_matches)} potential text sections:")
        for i, match in enumerate(text_matches[:5]):
            try:
                text = match.decode("ascii", errors="replace").strip()
                if text:
                    print(f"  {i+1}: {text[:100]}{'...' if len(text) > 100 else ''}")
            except:
                pass

    # Look for file extensions
    extensions = re.findall(rb"\.[a-zA-Z0-9]{2,4}\b", data)
    if extensions:
        unique_ext = set(ext.decode("ascii", errors="replace") for ext in extensions)
        print(f"\nPotential file extensions found: {', '.join(sorted(unique_ext))}")


if __name__ == "__main__":
    decode_and_extract()
