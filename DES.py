import struct
import secrets
import string

class __Random():
    @staticmethod
    def Random_ASCII (length :int) -> str:
        characters = string.ascii_letters + string.digits
        random_string = ''.join(secrets.choice(characters) for _ in range(length))

        return random_string

    @staticmethod
    def Random_Bytes (num_bytes: int) -> bytes:
        return secrets.token_bytes(num_bytes)

class Des(__Random):
    # Initial Permutation Table for DES (IP)
    __INITIAL_PERMUTATION: tuple[int]= [
    57, 49, 41, 33, 25, 17, 9,  1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
    56, 48, 40, 32, 24, 16, 8,  0,
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    ]
    
    # Inverse Or Final permutation IP^-1 (FP) 
    __INVERSE_PERMUTATION: tuple[int] = [
        39, 7,  47, 15, 55, 23, 63, 31,
        38, 6,  46, 14, 54, 22, 62, 30,
        37, 5,  45, 13, 53, 21, 61, 29,
        36, 4,  44, 12, 52, 20, 60, 28,
        35, 3,  43, 11, 51, 19, 59, 27,
        34, 2,  42, 10, 50, 18, 58, 26,
        33, 1,  41, 9,  49, 17, 57, 25,
        32, 0,  40, 8,  48, 16, 56, 24,
    ]
    
    # Permuted Choice 1 (PC1) table
    __PERMUTED_CHOICE1: tuple[int] = [
        56, 48, 40, 32, 24, 16, 8,
        0,  57, 49, 41, 33, 25, 17,
        9,  1,  58, 50, 42, 34, 26,
        18, 10, 2,  59, 51, 43, 35,
        62, 54, 46, 38, 30, 22, 14,
        6,  61, 53, 45, 37, 29, 21,
        13, 5,  60, 52, 44, 36, 28,
        20, 12, 4,  27, 19, 11, 3,
    ]

    # PC2: Compression permutation table
    __PERMUTED_CHOICE2: tuple[int] = [
        13, 16, 10, 23, 0,  4,
        2,  27, 14, 5,  20, 9,
        22, 18, 11, 3,  25, 7,
        15, 6,  26, 19, 12, 1,
        40, 51, 30, 36, 46, 54,
        29, 39, 50, 44, 32, 47,
        43, 48, 38, 55, 33, 52,
        45, 41, 49, 35, 28, 31,
    ]

    # expansion operation matrix
    __EXPANSION: tuple[int] = [
        31, 0,  1,  2,  3,  4,
        3,  4,  5,  6,  7,  8,
        7,  8,  9,  10, 11, 12,
        11, 12, 13, 14, 15, 16,
        15, 16, 17, 18, 19, 20,
        19, 20, 21, 22, 23, 24,
        23, 24, 25, 26, 27, 28,
        27, 28, 29, 30, 31, 0,
    ]

    # 8 Substitution Box
    __SBOX: tuple[tuple[int]] = [
        (
            14, 4,  13, 1,  2,  15, 11, 8,  3,  10, 6,  12, 5,  9,  0,  7,
            0,  15, 7,  4,  14, 2,  13, 1,  10, 6,  12, 11, 9,  5,  3,  8,
            4,  1,  14, 8,  13, 6,  2,  11, 15, 12, 9,  7,  3,  10, 5,  0,
            15, 12, 8,  2,  4,  9,  1,  7,  5,  11, 3,  14, 10, 0,  6,  13,
        ),
        (
            15, 1,  8,  14, 6,  11, 3,  4,  9,  7,  2,  13, 12, 0,  5,  10,
            3,  13, 4,  7,  15, 2,  8,  14, 12, 0,  1,  10, 6,  9,  11, 5,
            0,  14, 7,  11, 10, 4,  13, 1,  5,  8,  12, 6,  9,  3,  2,  15,
            13, 8,  10, 1,  3,  15, 4,  2,  11, 6,  7,  12, 0,  5,  14, 9,
        ),
        (
            10, 0,  9,  14, 6,  3,  15, 5,  1,  13, 12, 7,  11, 4,  2,  8,
            13, 7,  0,  9,  3,  4,  6,  10, 2,  8,  5,  14, 12, 11, 15, 1,
            13, 6,  4,  9,  8,  15, 3,  0,  11, 1,  2,  12, 5,  10, 14, 7,
            1,  10, 13, 0,  6,  9,  8,  7,  4,  15, 14, 3,  11, 5,  2,  12,
        ),
        (
            7,  13, 14, 3,  0,  6,  9,  10, 1,  2,  8,  5,  11, 12, 4,  15,
            13, 8,  11, 5,  6,  15, 0,  3,  4,  7,  2,  12, 1,  10, 14, 9,
            10, 6,  9,  0,  12, 11, 7,  13, 15, 1,  3,  14, 5,  2,  8,  4,
            3,  15, 0,  6,  10, 1,  13, 8,  9,  4,  5,  11, 12, 7,  2,  14,
        ),
        (
            2,  12, 4,  1,  7,  10, 11, 6,  8,  5,  3,  15, 13, 0,  14, 9,
            14, 11, 2,  12, 4,  7,  13, 1,  5,  0,  15, 10, 3,  9,  8,  6,
            4,  2,  1,  11, 10, 13, 7,  8,  15, 9,  12, 5,  6,  3,  0,  14,
            11, 8,  12, 7,  1,  14, 2,  13, 6,  15, 0,  9,  10, 4,  5,  3,
        ),
        (
            12, 1,  10, 15, 9,  2,  6,  8,  0,  13, 3,  4,  14, 7,  5,  11,
            10, 15, 4,  2,  7,  12, 9,  5,  6,  1,  13, 14, 0,  11, 3,  8,
            9,  14, 15, 5,  2,  8,  12, 3,  7,  0,  4,  10, 1,  13, 11, 6,
            4,  3,  2,  12, 9,  5,  15, 10, 11, 14, 1,  7,  6,  0,  8,  13,
        ),
        (
            4,  11,  2, 14, 15, 0,  8,  13, 3,  12, 9,  7,  5,  10, 6,  1,
            13, 0,  11, 7,  4,  9,  1,  10, 14, 3,  5,  12, 2,  15, 8,  6,
            1,  4,  11, 13, 12, 3,  7,  14, 10, 15, 6,  8,  0,  5,  9,  2,
            6,  11, 13, 8,  1,  4,  10, 7,  9,  5,  0,  15, 14, 2,  3,  12,
        ),
        (
            13, 2,  8,  4,  6,  15, 11, 1,  10, 9,  3,  14, 5,  0,  12, 7,
            1,  15, 13, 8,  10, 3,  7,  4,  12, 5,  6,  11, 0,  14, 9,  2,
            7,  11, 4,  1,  9,  12, 14, 2,  0,  6,  10, 13, 15, 3,  5,  8,
            2,  1,  14, 7,  4,  10, 8,  13, 15, 12, 9,  0,  3,  5,  6,  11,
        ),
    ]

    # 32-bit permutation function P used on the output of the S-boxes
    __P32_SBOX: tuple[int] = [
        15, 6,  19, 20, 28, 11, 27, 16,
        0,  14, 22, 25, 4,  17, 30, 9,
        1,  7,  23, 13, 31, 26, 2,  8,
        18, 12, 29, 5,  21, 10, 3,  24,
    ]

    # Key schedule shifts
    __SHIFTS: tuple[int] = [
        1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1,
    ]

    def __init__(self) -> None:
        self.__plain_text  : bytes                   = '\0'
        self.__key         : bytes | bytearray       = '\0'
        self.__subkey      : tuple[tuple[int, ...]]  = ()

    @property
    def INITIAL_PERMUTATION(self):
        return type(self).__INITIAL_PERMUTATION
    
    @property
    def INVERSE_PERMUTATION(self):
        return type(self).__INVERSE_PERMUTATION
    
    @property
    def PERMUTED_CHOICE1(self):
        return type(self).__PERMUTED_CHOICE1
    
    @property
    def PERMUTED_CHOICE2(self):
        return type(self).__PERMUTED_CHOICE2
    
    @property
    def EXPANSION(self):
        return type(self).__EXPANSION
    
    @property
    def SBOX(self):
        return type(self).__SBOX
    
    @property
    def P32_SBOX(self):
        return type(self).__P32_SBOX
    
    @property
    def SHIFTS(self):
        return type(self).__SHIFTS
        
    @staticmethod
    def __left_circular_shift(i28: int, k: int) -> int:
        return i28 << k & 0x0fffffff | i28 >> 28 - k

    @staticmethod
    def __permute(data: int, bits: int, mapper: tuple[int]) -> int:
        ret = 0
        for i, v in enumerate(mapper):
            if data & 1 << bits - 1 - v:
                ret |= 1 << len(mapper) - 1 - i
        return ret

    def __feistel(self, right_block: list[int], key: int) -> int:
        # Step 1: Expansion /Permutation (input: 32 bits , output: 48 bits)
        expanded_right = self.__permute(right_block, 32, self.EXPANSION) 
        
        # Step 2: XOR with the subkey (input/output : 48 bits)
        xor_result = expanded_right ^ key

        # Step 3: S-Box substitution (input: 48bits, output: 32 bits)
        ret = 0
        for i, box in enumerate(self.SBOX):
            i6 = xor_result >> 42 - i * 6 & 0x3f
            ret = ret << 4 | box[i6 & 0x20 | (i6 & 0x01) << 4 | (i6 & 0x1e) >> 1]

        # Step 4: 32-bit permutation after s-box
        return self.__permute(ret, 32, self.P32_SBOX)


    def __key_schedule(self, key: bytes):
        # Get the 56-bit key from PC1
        keys, = struct.unpack(">Q", key[:8])
        next_key = self.__permute(keys, 64, self.PERMUTED_CHOICE1) & 0xFFFFFFFFFFFFFF 

        # Split the keys to 28 bit each
        left_half = (next_key >> 28)
        right_half = next_key & 0x0FFFFFFF  

        for bits in self.SHIFTS:
            left_half = self.__left_circular_shift(left_half, bits)
            right_half = self.__left_circular_shift(right_half, bits)

            # Combine back into a single integer (56 bit)
            combined_key = (left_half << 28) | right_half

            # Get the 48 bits subkey based on PC2
            yield self.__permute(combined_key, 56, self.PERMUTED_CHOICE2)

    def __encode_block(self, data_block: int, key: tuple[int], encryption: bool) -> int:
        # Initial permute the 64 bits block (8 bytes) of plain text
        permuted_block = self.__permute(data_block, 64, self.INITIAL_PERMUTATION)

        # Split the permuted block into left and right (32 bits each)
        left = permuted_block >> 32
        right = permuted_block & 0xFFFFFFFF

        # Reverse keys if decryption
        if not encryption:
            key = reversed(key)

        for subkey in key:
            new_left = right                               # Right becomes new left
            right = left ^ self.__feistel(right, subkey)   # XOR left with the feistel function

            # Update for the next round
            left, right = new_left, right

        # Combine halves becoming 64 bits
        combined_block = (right << 32) | left

        # Apply Final Permutation
        return self.__permute(combined_block, 64, self.INVERSE_PERMUTATION)
    

    def __Encode(self, block:bytes, key, encryption):
        for k in key:
            block = self.__encode_block(block, k, encryption)
            encryption = not encryption
        return block

    def __ECB(self, blocks, key, encryption):
        for block in blocks:
            yield self.__Encode(block, key, encryption)
        
    def __GenerateSubKeys(self):
        k0, k1, k2 = self.__key[:8], self.__key[8:16], self.__key[16:]
        if k1 == k2:
            self.__key = k0
            return tuple(self.__key_schedule(self.__key)),

        k2 = k2 or k0
        if k1 == k0:
            self.__key = k2
            return tuple(self.__key_schedule(self.__key)),
        
        return tuple(tuple(self.__key_schedule(k)) for k in (k0, k1, k2))
    
    def __encrypt(self) -> bytes:
        # Slice message to be 8 bytes or 64 bits each per block
        blocks: list[int] = []
        for i in range(0, len(self.__plain_text), 8):
            block_bytes = self.__plain_text[i:i + 8]
            # pad with zeros if it's not reaching 8 bytes
            block = struct.unpack(">Q", block_bytes.ljust(8, b'\0'))[0] 
            blocks.append(block)  

        # Generate 16 subkeys for encryptions    
        self.__subkey = self.__GenerateSubKeys()

        # Encrypt each blocks
        encoded_blocks = self.__ECB(blocks, self.__subkey, True)

        result = b"".join(struct.pack(">Q", block) for block in encoded_blocks)
        return result
    
    def __decrypt(self, cipher_text: bytes) -> bytes:
        # Slice message to be 8 bytes or 64 bits each per block
        blocks: list[int] = []
        for i in range(0, len(cipher_text), 8):
            block_bytes = cipher_text[i:i + 8]
            # pad with zeros if it's not reaching 8 bytes
            block = struct.unpack(">Q", block_bytes.ljust(8, b'\0'))[0] 
            blocks.append(block)  

        # Decrypt each blocks
        encoded_blocks = self.__ECB(blocks, self.__subkey[::-1], False)

        result = b"".join(struct.pack(">Q", block) for block in encoded_blocks)
        return result.rstrip(b'\x00')
    
    def derive_keys(self, key):
        key, = struct.unpack(">Q", key)
        next_key = self.__permute(key, 64, self.PERMUTED_CHOICE1)
        next_key = next_key >> 28, next_key & 0x0fffffff
        for bits in self.SHIFTS:
            next_key = self.__left_circular_shift(next_key[0], bits), self.__left_circular_shift(next_key[1], bits)
            yield self.__permute(next_key[0] << 28 | next_key[1], 56, self.PERMUTED_CHOICE2)

    def Encrypt(self, plain_text: bytes, key: bytes | bytearray) -> bytes:
        if isinstance(key, bytearray):
            key = bytes(key)

        assert isinstance(key, bytes), "The key should be bytes or bytearray"
        assert len(key) in (8, 16, 24), "The key should be of length 8 bytes, 16 bytes, or 24 bytes"
        
        self.__plain_text = plain_text
        self.__key = key

        return self.__encrypt()

    
    def Decrypt(self, cipher_text: bytes) -> bytes:
        return self.__decrypt(cipher_text) 

    def Decrypt_using_key(self, cipher_text: bytes, key: bytes | bytearray):        
        if isinstance(key, bytearray):
            key = bytes(key)

        assert isinstance(key, bytes), "The key should be bytes or bytearray"
        assert len(key) in (8, 16, 24), "The key should be 8 bytes, 16 bytes, or 24 bytes"

        blocks: list[int] = []
        for i in range(0, len(cipher_text), 8):
            block_bytes = cipher_text[i:i + 8]
            block = struct.unpack(">Q", block_bytes.ljust(8, b'\0'))[0] 
            blocks.append(block) 

        # Determine how many keys
        keys = None
        k0, k1, k2 = key[:8], key[8:16], key[16:]
        if k1 == k2:
            key = k0
            keys =  tuple(self.__key_schedule(key)),
        k2 = k2 or k0
        if k1 == k0:
            key = k2
            keys = tuple(self.__key_schedule(key)),
        
        if keys == None:
            keys = tuple(tuple(self.__key_schedule(k)) for k in (k0, k1, k2))
    
        # Decrypt each blocks using key
        encoded_blocks = self.__ECB(blocks, keys[::-1], False)

        result = b"".join(struct.pack(">Q", block) for block in encoded_blocks)
        return result.rstrip(b'\x00')
