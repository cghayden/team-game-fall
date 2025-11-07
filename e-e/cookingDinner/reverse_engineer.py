#!/usr/bin/env python3

def reverse_engineer_input():
    """Work backwards from expected output to find the input string"""
    
    # Expected output: 0È>êÀÏÈ5êÞ×ÓÜ
    expected_output = "0È>êÀÏÈ5êÞ×ÓÜ"
    
    print(f"Expected output: {expected_output}")
    print(f"Length: {len(expected_output)} characters")
    print()
    
    # Convert to ASCII values
    output_ascii = [ord(c) for c in expected_output]
    print("Output ASCII values:")
    for i, (char, ascii_val) in enumerate(zip(expected_output, output_ascii)):
        print(f"  {i+1:2}: '{char}' = {ascii_val}")
    print()
    
    # Reverse the transformation: output = 181 XOR (input + 50)
    # Therefore: input + 50 = 181 XOR output
    # Therefore: input = (181 XOR output) - 50
    
    input_chars = []
    print("Reverse engineering input:")
    
    for i, output_val in enumerate(output_ascii):
        # Calculate what (input + 50) should be
        input_plus_50 = 181 ^ output_val
        
        # Calculate the original input character
        input_val = input_plus_50 - 50
        
        # Convert to character if it's printable
        if 32 <= input_val <= 126:  # printable ASCII range
            input_char = chr(input_val)
        else:
            input_char = f"[{input_val}]"
        
        input_chars.append(input_char if 32 <= input_val <= 126 else None)
        
        print(f"  {i+1:2}: '{expected_output[i]}' ({output_val}) -> {input_plus_50} -> {input_val} -> '{input_char}'")
    
    print()
    
    # Build the input string (only from valid characters)
    valid_input_chars = [c for c in input_chars if c is not None]
    input_string = ''.join(valid_input_chars)
    
    print(f"Reconstructed input: {input_string}")
    print(f"Length: {len(valid_input_chars)} characters")
    
    # Check if it matches the expected pattern SKY-CCCC-nnnn
    print(f"\nPattern analysis:")
    if len(input_string) >= 12:
        print(f"  Position 1-3: {input_string[:3]} (should be 'SKY')")
        print(f"  Position 4: {input_string[3]} (should be '-')")
        print(f"  Position 5-8: {input_string[4:8]} (should be 4 capital letters)")
        print(f"  Position 9: {input_string[8]} (should be '-')")
        print(f"  Position 10-13: {input_string[9:13]} (should be 4 digits)")
    
    return input_string, valid_input_chars

if __name__ == "__main__":
    reverse_engineer_input()