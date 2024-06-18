from Crypto.Util.Padding import pad

#initial permutation (IP) table
IP=[
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

#final permutation (FP) table
FP=[
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

#expansion (E) table
E=[
    32, 1, 2, 3, 4, 5, 
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13, 
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

#S-boxes
S_BOX=[
    #S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    #S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    #S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8], 
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    #S4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    #S5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    #S6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    #S7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    #S8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ],
]

#permutation (P) table
P=[
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
]

#permutation choice 1 (PC-1) table
PC1=[
    57, 49, 41, 33, 25, 17, 9, 
    1, 58, 50, 42, 34, 26, 18, 
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]

#permutation choice 2 (PC-2) table
PC2=[
    14, 17, 11, 24, 1, 5, 3, 28,
    15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32
]

#left rotations schedule for key
LEFT_ROTATION=[1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


#initial permutation (IP) function
def permute(block, table):
    return [block[x - 1]for x in table]


#split block into two halves
def split_block(block):
    return block[:len(block)//2], block[len(block)//2:]


#expansion permutation
def expansion_permutation(block):
    return permute(block, E)


#XOR operation
def xor(a, b):
    return [x ^ y for x, y in zip(a, b)]


#subtitution using S-boxes
def subtitute(expanded_half_block):
    sun_block = [expanded_half_block[k:k+6] for k in range(0, len(expanded_half_block), 6)]
    result=[]
    for i, block in enumerate(sun_block):
        row = int(str(block[0]) + str(block[5]), 2)
        col = int(''.join(map(str, block[1:5])), 2)
        result += [int(x) for x in format(S_BOX[i][row][col], '04b')]
    return result


#permutation P
def permutation(block):
    return permute(block, P)


#feistel function
def feistel(right_half_block, subkey):
    expanded_half_block = expansion_permutation(right_half_block)
    xor_result = xor(expanded_half_block, subkey)
    substituted_half_block = subtitute(xor_result)
    permuted_half_block = permutation(substituted_half_block)
    return permuted_half_block


#generate 16 subkeys
def generate_subkeys(key):
    key = permute(key, PC1)
    left, right = split_block(key)
    subkeys = []
    for i in range(16):
        left = left[LEFT_ROTATION[i]:] + left[:LEFT_ROTATION[i]]
        right = right[LEFT_ROTATION[i]:] + right[:LEFT_ROTATION[i]]
        combined_key = left + right
        subkeys.append(permute(combined_key, PC2))
    return subkeys


#convert hex to binary
def text_to_bin(text):
    return [int(bit) for char in text.encode('utf-8') for bit in format(char, '08b')]


#convert binary to hex
def bin_to_text(binlist):
    return ''.join([chr(int(''.join(map(str, binlist[i:i + 8])), 2)) for i in range(0, len(binlist), 8)])


def bin_to_hex(binlist):
    return format(int(''.join(map(str, binlist)), 2), '016x')


#convert hex to text
def hex_to_text(hex_string):
    bytes_object = bytes.fromhex(hex_string)
    return bytes_object.decode('utf-8', errors='ignore')


def pad_plaintext(plaintext):
    padded_text = pad(plaintext.encode('utf-8'), 8) #pad to 64- bit block size
    return [int(bit) for byte in padded_text for bit in format(byte, '08b')]


#DES encryption function for a single block
def des_encrypt_block(block, subkeys):
    permuted_text = permute(block, IP)
    left, right = split_block(permuted_text)

    for i in range(16):
        temp = right
        right = xor(left, feistel(right, subkeys[i]))
        left = temp

        ciphertext = []

        pre_output = right + left
        ciphertext = permute(pre_output, FP)
        return ciphertext
    


def des_encrypt(plaintext, key):
    plaintext_padded_bin = pad_plaintext(plaintext)
    key_bin = pad_plaintext(key)[:64]

    subkeys = generate_subkeys(key_bin)
    ciphertext = []

    for i in range(0, len(plaintext_padded_bin), 64):
        block = plaintext_padded_bin[i:i + 64]
        encrypted_block = des_encrypt_block(block, subkeys)
        ciphertext.extend(encrypted_block)

    hex_ciphertext = bin_to_hex(ciphertext)
    char_ciphertext = hex_to_text(hex_ciphertext)

    return hex_ciphertext, char_ciphertext
    

#contoh penggunaan
key = "UNGGULAN"
plaintext = "KARIMATA"

hex_ciphertext, char_ciphertext = des_encrypt(plaintext, key)

print("plaintext:", plaintext)
print("hex ciphertext:", hex_ciphertext)
print("char ciphertext:", char_ciphertext)