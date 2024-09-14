# 1. Define Block and Key Sizes
BLOCK_SIZE = 8  # Each block is 8 bits (1 byte)
KEY_SIZE = 8    # The key is also 8 bits

# 2. Define Substitution Box (S-box)
# This is a predefined 4x4 S-box, which introduces non-linearity (confusion) in the encryption process.
S_BOX = [0xE, 0x4, 0xD, 0x1,
         0x2, 0xF, 0xB, 0x8,
         0x3, 0xA, 0x6, 0xC,
         0x5, 0x9, 0x0, 0x7]

# Function to substitute 4-bit values using the S-box
def substitute_4bits(input_value):
    """Substitute 4-bit value using S-Box"""
    return S_BOX[input_value]

# 3. Define Permutation Function
# This is the permutation table that rearranges the bits to provide diffusion.
PERMUTATION_TABLE = [3, 0, 2, 4, 6, 1, 7, 5]

# Function to permute an 8-bit block according to the permutation table
def permute(block):
    """Permute 8-bit block using the permutation table"""
    # Convert the block to an 8-bit binary string
    block_str = f'{block:08b}'  
    # Permute the bits based on the table and join them into a new string
    permuted = ''.join([block_str[PERMUTATION_TABLE[i]] for i in range(BLOCK_SIZE)])
    # Convert the permuted string back into an integer
    return int(permuted, 2)

# 4. Feistel Function
# This function takes the right half of the block and XORs it with the key.
def feistel_function(right_half, key):
    """Feistel function: XOR right half of the block with the key"""
    return right_half ^ key

# 5. Combine Components for Single-Round Encryption
# This function performs a single round of block encryption using S-box, permutation, and Feistel function.
def encrypt_block(plaintext, key):
    """Encrypt a single 8-bit block"""
    # Split the block into left and right halves (4 bits each)
    left_half = (plaintext >> 4) & 0xF  # Top 4 bits
    right_half = plaintext & 0xF  # Bottom 4 bits
    
    # Substitution using the S-box on the right half
    right_half_sub = substitute_4bits(right_half)
    
    # Feistel function: XOR left half with the substituted right half
    feistel_out = feistel_function(left_half, right_half_sub)
    
    # Combine the left and right halves
    combined = (feistel_out << 4) | right_half_sub
    
    # Permute the combined block
    permuted_block = permute(combined)
    
    return permuted_block

# ECB Mode Implementation
# Encrypts multiple blocks independently of each other.
def ecb_mode_encrypt(plaintext_blocks, key):
    """Encrypt multiple blocks in ECB mode"""
    return [encrypt_block(block, key) for block in plaintext_blocks]

# Decrypts multiple blocks independently in ECB mode (symmetric to encryption).
def ecb_mode_decrypt(ciphertext_blocks, key):
    """Decrypt multiple blocks in ECB mode"""
    return [encrypt_block(block, key) for block in ciphertext_blocks]

# CBC Mode Implementation
# XORs the current plaintext block with the previous ciphertext block for added security.
def xor_blocks(block1, block2):
    """XOR two 8-bit blocks"""
    return block1 ^ block2

# Encrypts blocks using CBC mode, where each block is XORed with the previous ciphertext block.
def cbc_mode_encrypt(plaintext_blocks, key, iv):
    """Encrypt multiple blocks in CBC mode"""
    ciphertext_blocks = []
    previous_block = iv  # Start with the initialization vector (IV)
    for block in plaintext_blocks:
        # XOR the current block with the previous ciphertext block (or IV for the first block)
        block_to_encrypt = xor_blocks(block, previous_block)
        # Encrypt the XORed block
        encrypted_block = encrypt_block(block_to_encrypt, key)
        # Append the encrypted block to the ciphertext list
        ciphertext_blocks.append(encrypted_block)
        # Update the previous block to the current ciphertext
        previous_block = encrypted_block
    return ciphertext_blocks

# Decrypts blocks using CBC mode, reversing the process of encryption by XORing with the previous ciphertext block.
def cbc_mode_decrypt(ciphertext_blocks, key, iv):
    """Decrypt multiple blocks in CBC mode"""
    plaintext_blocks = []
    previous_block = iv  # Start with the initialization vector (IV)
    for block in ciphertext_blocks:
        # Decrypt the current ciphertext block
        decrypted_block = encrypt_block(block, key)
        # XOR the decrypted block with the previous ciphertext block (or IV for the first block)
        plaintext_block = xor_blocks(decrypted_block, previous_block)
        # Append the decrypted block to the plaintext list
        plaintext_blocks.append(plaintext_block)
        # Update the previous block to the current ciphertext
        previous_block = block
    return plaintext_blocks

# Example usage for ECB and CBC modes
def main():
    # Test data
    plaintext_blocks = [0b11001101, 0b10011001]  # Two 8-bit blocks (205 and 153 in decimal)
    key = 0b10101010                             # 8-bit key
    iv = 0b10101010                              # Initialization vector (IV)

    # ECB Mode Example
    print("ECB Mode = ")
    # Encrypt plaintext blocks using ECB mode
    ciphertext_blocks_ecb = ecb_mode_encrypt(plaintext_blocks, key)
    print(f"ECB Ciphertext blocks: {[bin(c) for c in ciphertext_blocks_ecb]}")

    # Decrypt ciphertext blocks back to plaintext using ECB mode
    decrypted_blocks_ecb = ecb_mode_decrypt(ciphertext_blocks_ecb, key)
    print(f"ECB Decrypted blocks: {[bin(d) for d in decrypted_blocks_ecb]}")

    # CBC Mode Example
    print("\nCBC Mode = ")
    # Encrypt plaintext blocks using CBC mode
    ciphertext_blocks_cbc = cbc_mode_encrypt(plaintext_blocks, key, iv)
    print(f"CBC Ciphertext blocks: {[bin(c) for c in ciphertext_blocks_cbc]}")

    # Decrypt ciphertext blocks back to plaintext using CBC mode
    decrypted_blocks_cbc = cbc_mode_decrypt(ciphertext_blocks_cbc, key, iv)
    print(f"CBC Decrypted blocks: {[bin(d) for d in decrypted_blocks_cbc]}")

if __name__ == "__main__":
    main()
