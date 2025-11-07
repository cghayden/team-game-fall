#!/usr/bin/env python3
"""
XMI-Reader Library Example
Demonstration of how to use the xmi-reader library for standard XMI files
"""

import xmi
import logging

def xmi_reader_example():
    """
    Example usage of xmi-reader library for standard XMI files
    """
    
    print("XMI-READER LIBRARY USAGE EXAMPLE")
    print("=" * 50)
    
    print("""
This demonstrates how to use the xmi-reader library version 0.5.9
for reading standard XMI, AWS, or HET files.

BASIC USAGE:
-----------
""")
    
    example_code = '''
import xmi

# Open an XMI file
xmi_obj = xmi.open_file("/path/to/file.xmi")

# List all datasets and members
for f in xmi_obj.get_files():
    if xmi_obj.is_pds(f):
        for m in xmi_obj.get_members(f):
            print("{}({})".format(f, m))
    else:
        print(f)

# Print JSON metadata
print(xmi_obj.get_json())

# Extract all files
xmi_obj.set_output_folder("/tmp/xmi_files/")
xmi_obj.extract_all()

# Print detailed information
xmi_obj.print_details()

# Check for messages
if xmi_obj.has_message():
    print(xmi_obj.get_message())
'''
    
    print(example_code)
    
    print("""
ADVANCED USAGE WITH DEBUG LOGGING:
----------------------------------
""")
    
    debug_code = '''
import logging
import xmi

# Enable debug logging
xmi_obj = xmi.XMIT(filename="/path/to/file.xmi", loglevel=logging.DEBUG)
xmi_obj.open()
'''
    
    print(debug_code)
    
    print("""
SUPPORTED FILE TYPES:
--------------------
- XMI (XMIT format) files
- AWS (AWSTAPE) files  
- HET (Hercules Emulated Tape) files

ARCHIVE.NETDATA.XMI ANALYSIS RESULTS:
------------------------------------
The file you provided (ARCHIVE.NETDATA.XMI) is NOT a standard XMI file.
Instead, it's a Base64-encoded ZIP archive containing:
- EMAILS file (989 bytes compressed → 5,520 bytes uncompressed)
- Q1-Q4 files (survey/quiz data)
- USERS file (user information)

The compression format appears to use a non-standard deflate implementation
that couldn't be decompressed with standard Python libraries.

For your specific file, use the analysis scripts we created:
- ultimate_xmi_reader.py (comprehensive analysis)
- ANALYSIS_SUMMARY.md (detailed findings)
""")

if __name__ == "__main__":
    xmi_reader_example()