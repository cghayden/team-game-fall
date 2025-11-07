#!/usr/bin/env python3

def test_first_character():
    """Test if 'S' produces '0' as the first output character"""
    
    # Input character 'S'
    input_char = ord('S')  # ASCII 83
    print(f"Input: 'S' (ASCII {input_char})")
    
    # Add 50 (unsalted butter value from recipe)
    modified_input = input_char + 50  # 133
    print(f"After adding 50: {modified_input}")
    
    # The other parameter passed to Meat Bread Layers is 181
    other_param = 181
    print(f"Other parameter: {other_param}")
    
    # Expected output is '0'
    expected_output = ord('0')  # ASCII 48
    print(f"Expected output: '0' (ASCII {expected_output})")
    
    # If this is some kind of XOR or mathematical operation
    # Let's try different possibilities
    
    print("\nTesting various operations:")
    print(f"133 XOR 181 = {133 ^ 181} (ASCII: '{chr(133 ^ 181) if 32 <= (133 ^ 181) <= 126 else 'non-printable'}')")
    print(f"181 XOR 133 = {181 ^ 133} (ASCII: '{chr(181 ^ 133) if 32 <= (181 ^ 133) <= 126 else 'non-printable'}')")
    print(f"133 - 181 = {133 - 181}")
    print(f"181 - 133 = {181 - 133} (ASCII: '{chr(181 - 133) if 32 <= (181 - 133) <= 126 else 'non-printable'}')")
    print(f"133 + 181 = {133 + 181}")
    print(f"133 % 181 = {133 % 181}")
    print(f"181 % 133 = {181 % 133}")
    
    # Check if 181 - 133 = 48 (which is '0')
    if 181 - 133 == expected_output:
        print(f"\n*** MATCH FOUND: 181 - 133 = {181 - 133} = ASCII '0' ***")
        return True
    
    return False

if __name__ == "__main__":
    test_first_character()