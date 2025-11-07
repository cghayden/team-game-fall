#!/usr/bin/env python3
"""
Simple XMI Reader Test
"""

import os
import base64

def test_simple():
    file_path = "/Users/corey/team-game-fall/forensics/mainframe/ARCHIVE.NETDATA.XMI"
    
    print("Testing XMI file reading...")
    
    # Read file
    with open(file_path, 'rb') as f:
        content = f.read()
    
    print(f"File size: {len(content)} bytes")
    
    # Decode base64
    lines = content.split(b'\n')
    base64_content = b''.join(line.strip() for line in lines if line.strip())
    
    decoded = base64.b64decode(base64_content)
    print(f"Decoded size: {len(decoded)} bytes")
    
    # Save decoded content
    with open("/tmp/decoded_xmi.bin", 'wb') as f:
        f.write(decoded)
    print("Decoded content saved to /tmp/decoded_xmi.bin")

if __name__ == "__main__":
    test_simple()