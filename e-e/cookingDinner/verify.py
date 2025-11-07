#!/usr/bin/env python3

def verify_transformation():
    """Verify that our found input produces the expected output"""
    
    input_string = "SKY-CHKN-9047"
    expected_output = "0È>êÀÏÈ5êÞ×ÓÜ"
    
    print(f"Input: {input_string}")
    print(f"Expected output: {expected_output}")
    print()
    
    # Apply the transformation: output = 181 XOR (input + 50)
    actual_output_chars = []
    
    print("Forward transformation:")
    for i, char in enumerate(input_string):
        input_ascii = ord(char)
        input_plus_50 = input_ascii + 50
        output_ascii = 181 ^ input_plus_50
        output_char = chr(output_ascii)
        
        actual_output_chars.append(output_char)
        
        expected_char = expected_output[i] if i < len(expected_output) else "?"
        match_status = "✓" if output_char == expected_char else "✗"
        
        print(f"  {i+1:2}: '{char}' ({input_ascii}) + 50 = {input_plus_50} XOR 181 = {output_ascii} = '{output_char}' {match_status}")
    
    actual_output = ''.join(actual_output_chars)
    
    print()
    print(f"Actual output:   {actual_output}")
    print(f"Expected output: {expected_output}")
    print(f"Match: {'✓ YES' if actual_output == expected_output else '✗ NO'}")
    
    return actual_output == expected_output

if __name__ == "__main__":
    verify_transformation()