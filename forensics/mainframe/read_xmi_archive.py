#!/usr/bin/env python3
"""
XMI Archive Reader Script
This script reads and analyzes the ARCHIVE.NETDATA.XMI file using the xmi-reader library.
"""

import xmi
import json
import os
import sys
from pathlib import Path


def main():
    # Path to the XMI file
    xmi_file_path = (
        "/Users/corey/team-game-fall/forensics/mainframe/ARCHIVE.NETDATA.XMI"
    )

    # Check if file exists
    if not os.path.exists(xmi_file_path):
        print(f"Error: File {xmi_file_path} not found!")
        sys.exit(1)

    print(f"Reading XMI file: {xmi_file_path}")
    print("=" * 60)

    try:
        # Open the XMI file
        xmi_obj = xmi.open_file(xmi_file_path)

        print("\n1. BASIC FILE INFORMATION")
        print("-" * 40)
        print(f"File size: {os.path.getsize(xmi_file_path)} bytes")

        # Print detailed information about the XMI file
        print("\n2. DETAILED XMI INFORMATION")
        print("-" * 40)
        xmi_obj.print_details()

        # Check if there's a message in the XMI
        print("\n3. XMI MESSAGE")
        print("-" * 40)
        if xmi_obj.has_message():
            message = xmi_obj.get_message()
            print(f"Message: {message}")
        else:
            print("No message found in XMI file")

        # List all datasets and dataset members
        print("\n4. FILES AND DATASETS")
        print("-" * 40)
        try:
            files = xmi_obj.get_files()
            if files:
                for f in files:
                    if xmi_obj.is_pds(f):
                        print(f"PDS Dataset: {f}")
                        try:
                            members = xmi_obj.get_members(f)
                            for m in members:
                                print(f"  Member: {f}({m})")
                        except Exception as e:
                            print(f"  Error reading members: {e}")
                    else:
                        print(f"File: {f}")
            else:
                print("No files found in XMI archive")
        except Exception as e:
            print(f"Error listing files: {e}")

        # Get JSON metadata
        print("\n5. JSON METADATA")
        print("-" * 40)
        try:
            json_metadata = xmi_obj.get_json()
            if json_metadata:
                print(json.dumps(json_metadata, indent=2))
            else:
                print("No JSON metadata available")
        except Exception as e:
            print(f"Error getting JSON metadata: {e}")

        # Extract files to a directory
        print("\n6. EXTRACTING FILES")
        print("-" * 40)
        extract_dir = "/tmp/xmi_archive_extracted"
        try:
            # Create extraction directory
            Path(extract_dir).mkdir(parents=True, exist_ok=True)

            # Set output folder and extract
            xmi_obj.set_output_folder(extract_dir)
            xmi_obj.set_quiet(False)  # Show extraction progress
            xmi_obj.extract_all()

            print(f"Files extracted to: {extract_dir}")

            # List extracted files
            if os.path.exists(extract_dir):
                extracted_files = []
                for root, dirs, files in os.walk(extract_dir):
                    for file in files:
                        rel_path = os.path.relpath(
                            os.path.join(root, file), extract_dir
                        )
                        extracted_files.append(rel_path)
                        print(f"  Extracted: {rel_path}")

                if not extracted_files:
                    print("  No files were extracted")

        except Exception as e:
            print(f"Error during extraction: {e}")

        print("\n7. SUMMARY")
        print("-" * 40)
        print(f"Successfully processed XMI file: {os.path.basename(xmi_file_path)}")

    except Exception as e:
        print(f"Error opening XMI file: {e}")
        print(f"Error type: {type(e).__name__}")

        # Try with debug logging enabled
        print("\nTrying with debug logging...")
        try:
            import logging

            logging.basicConfig(level=logging.DEBUG)
            xmi_obj_debug = xmi.XMIT(filename=xmi_file_path, loglevel=logging.DEBUG)
            xmi_obj_debug.open()
        except Exception as debug_e:
            print(f"Debug attempt also failed: {debug_e}")


def analyze_file_content():
    """Additional analysis of the XMI file content"""
    xmi_file_path = (
        "/Users/corey/team-game-fall/forensics/mainframe/ARCHIVE.NETDATA.XMI"
    )

    print("\n" + "=" * 60)
    print("ADDITIONAL FILE ANALYSIS")
    print("=" * 60)

    # Read first few lines to understand structure
    try:
        with open(xmi_file_path, "rb") as f:
            first_bytes = f.read(100)
            print(f"First 100 bytes (hex): {first_bytes.hex()}")

        # Try to read as text
        with open(xmi_file_path, "r", encoding="utf-8", errors="ignore") as f:
            first_lines = [f.readline().strip() for _ in range(5)]
            print("\nFirst 5 lines as text:")
            for i, line in enumerate(first_lines, 1):
                print(f"  {i}: {line[:100]}{'...' if len(line) > 100 else ''}")

    except Exception as e:
        print(f"Error reading file content: {e}")


if __name__ == "__main__":
    main()
    analyze_file_content()
