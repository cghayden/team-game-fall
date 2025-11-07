#!/usr/bin/env python3
"""
Comprehensive XMI Archive Analyzer
This script tries multiple methods to extract and analyze the ARCHIVE.NETDATA.XMI file
"""

import os
import sys
import base64
import zipfile
import struct
import io
from pathlib import Path


def comprehensive_analysis():
    """Comprehensive analysis of the XMI file"""
    file_path = "/Users/corey/team-game-fall/forensics/mainframe/ARCHIVE.NETDATA.XMI"

    print("COMPREHENSIVE XMI ARCHIVE ANALYZER")
    print("=" * 60)

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

    # Method 1: Try to find and extract individual ZIP entries
    print("\nMETHOD 1: Individual ZIP Entry Extraction")
    print("-" * 40)
    extract_individual_entries(decoded)

    # Method 2: Analyze the structure byte by byte
    print("\nMETHOD 2: Structural Analysis")
    print("-" * 40)
    analyze_structure(decoded)

    # Method 3: Search for readable content
    print("\nMETHOD 3: Content Analysis")
    print("-" * 40)
    analyze_content(decoded)


def extract_individual_entries(data):
    """Try to extract individual ZIP entries"""
    pos = 0
    entry_count = 0

    while True:
        # Find local file header
        lfh_pos = data.find(b"PK\x03\x04", pos)
        if lfh_pos == -1:
            break

        entry_count += 1
        print(f"Entry {entry_count} at position {lfh_pos}")

        try:
            # Parse local file header
            if lfh_pos + 30 > len(data):
                break

            header = data[lfh_pos : lfh_pos + 30]

            # Unpack the local file header
            (
                signature,
                version,
                flags,
                method,
                mod_time,
                mod_date,
                crc32,
                comp_size,
                uncomp_size,
                name_len,
                extra_len,
            ) = struct.unpack("<LHHHHHLLLHH", header)

            print(f"  Signature: {signature:08x}")
            print(f"  Compression method: {method}")
            print(f"  Compressed size: {comp_size:,}")
            print(f"  Uncompressed size: {uncomp_size:,}")
            print(f"  Filename length: {name_len}")

            # Extract filename
            name_start = lfh_pos + 30
            name_end = name_start + name_len

            if name_end <= len(data):
                filename = data[name_start:name_end]
                print(f"  Filename: {filename.decode('utf-8', errors='replace')}")

                # Extract file data
                data_start = name_end + extra_len
                data_end = data_start + comp_size

                if data_end <= len(data):
                    file_data = data[data_start:data_end]

                    # Try to decompress if compressed
                    if method == 8:  # Deflate
                        try:
                            import zlib

                            decompressed = zlib.decompress(
                                file_data, -15
                            )  # Raw deflate
                            print(
                                f"  Successfully decompressed: {len(decompressed)} bytes"
                            )

                            # Save decompressed file
                            output_dir = "/tmp/xmi_extracted"
                            Path(output_dir).mkdir(parents=True, exist_ok=True)

                            safe_filename = filename.decode(
                                "utf-8", errors="replace"
                            ).replace("/", "_")
                            output_path = os.path.join(
                                output_dir, f"entry_{entry_count}_{safe_filename}"
                            )

                            with open(output_path, "wb") as f:
                                f.write(decompressed)
                            print(f"  Saved to: {output_path}")

                            # Analyze the extracted file
                            analyze_extracted_file(output_path, decompressed)

                        except Exception as e:
                            print(f"  Decompression failed: {e}")
                    elif method == 0:  # No compression
                        print(f"  Uncompressed data: {len(file_data)} bytes")
                        # Save uncompressed file
                        output_dir = "/tmp/xmi_extracted"
                        Path(output_dir).mkdir(parents=True, exist_ok=True)

                        safe_filename = filename.decode(
                            "utf-8", errors="replace"
                        ).replace("/", "_")
                        output_path = os.path.join(
                            output_dir, f"entry_{entry_count}_{safe_filename}"
                        )

                        with open(output_path, "wb") as f:
                            f.write(file_data)
                        print(f"  Saved to: {output_path}")

                        analyze_extracted_file(output_path, file_data)

                    pos = data_end
                else:
                    pos = lfh_pos + 4
            else:
                pos = lfh_pos + 4

        except Exception as e:
            print(f"  Error processing entry: {e}")
            pos = lfh_pos + 4

    print(f"Found {entry_count} ZIP entries")


def analyze_extracted_file(file_path, data):
    """Analyze an extracted file"""
    print(f"    Analyzing extracted file:")

    # Check if it's text
    try:
        text = data.decode("utf-8")
        print(f"      UTF-8 text file ({len(text)} characters)")

        # Show first few lines
        lines = text.split("\n")[:5]
        for i, line in enumerate(lines):
            if line.strip():
                print(
                    f"        Line {i+1}: {line.strip()[:80]}{'...' if len(line.strip()) > 80 else ''}"
                )

        # Look for interesting patterns
        import re

        # Email addresses
        emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)
        if emails:
            print(
                f"      Found {len(emails)} email addresses: {emails[:3]}{'...' if len(emails) > 3 else ''}"
            )

        # URLs
        urls = re.findall(r'https?://[^\s<>"{}|\\^`[\]]+', text)
        if urls:
            print(
                f"      Found {len(urls)} URLs: {urls[:3]}{'...' if len(urls) > 3 else ''}"
            )

    except UnicodeDecodeError:
        print(f"      Binary file ({len(data)} bytes)")
        print(f"      First 40 bytes (hex): {data[:40].hex()}")

        # Check for common file types
        if data.startswith(b"\x89PNG"):
            print(f"      -> PNG image")
        elif data.startswith(b"\xff\xd8\xff"):
            print(f"      -> JPEG image")
        elif data.startswith(b"%PDF"):
            print(f"      -> PDF document")
        elif data.startswith(b"GIF8"):
            print(f"      -> GIF image")
        elif b"<html" in data[:100].lower():
            print(f"      -> HTML document")


def analyze_structure(data):
    """Analyze the overall structure of the decoded data"""
    print(f"Total decoded size: {len(data):,} bytes")

    # Find all PK signatures
    signatures = [b"PK\x03\x04", b"PK\x01\x02", b"PK\x05\x06", b"PK\x07\x08"]
    sig_names = [
        "Local File Header",
        "Central Directory",
        "End of Central Directory",
        "Data Descriptor",
    ]

    for sig, name in zip(signatures, sig_names):
        positions = []
        pos = 0
        while True:
            pos = data.find(sig, pos)
            if pos == -1:
                break
            positions.append(pos)
            pos += 4

        if positions:
            print(f"{name} ({sig.hex()}): {len(positions)} found at {positions}")


def analyze_content(data):
    """Analyze the content for readable information"""

    # Try different encodings
    encodings = ["utf-8", "latin-1", "cp1252", "ascii"]

    for encoding in encodings:
        try:
            text = data.decode(encoding, errors="ignore")

            # Look for meaningful text (sequences of printable characters)
            import re

            text_blocks = re.findall(r"[A-Za-z0-9\s\.,;:!?\-_(){}[\]]{50,}", text)

            if text_blocks:
                print(
                    f"Readable text blocks with {encoding} encoding: {len(text_blocks)}"
                )
                for i, block in enumerate(text_blocks[:3]):
                    clean_block = " ".join(block.split())  # Clean whitespace
                    print(
                        f"  Block {i+1}: {clean_block[:100]}{'...' if len(clean_block) > 100 else ''}"
                    )
                break
        except:
            continue


if __name__ == "__main__":
    comprehensive_analysis()
