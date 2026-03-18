from z3 import *

# Create Z3 solver
s = Solver()

# Create 43 byte variables for the flag (0-255 range)
Flag = [BitVec(f'Flag_{i}', 8) for i in range(43)]

# Create the three bRam variables
bRam0 = BitVec('bRam0', 8)
bRam1 = BitVec('bRam1', 8)
bRam2 = BitVec('bRam2', 8)

# Add constraint that all flag bytes must be printable ASCII (32-126)
for i in range(43):
    s.add(Flag[i] >= 32)
    s.add(Flag[i] <= 126)

# Add all constraints from the WASM check function
# Constraint 1
s.add((Flag[6] + Flag[38] - Flag[31] - 
       ((Flag[3] & (Flag[21] ^ Flag[41]) - (Flag[12] | Flag[13]) * Flag[26]) |
        (bRam2 | Flag[35] + Flag[39])) |
       Flag[20] - (Flag[4] - Flag[30])) == 0x6e)

# Constraint 2
s.add((Flag[10] | Flag[36]) == 0x5f)

# Constraint 3
s.add(((Flag[27] ^ Flag[8]) & Flag[15]) == 0x2d)

# Constraint 4
s.add(((Flag[33] ^ bRam1 * (Flag[42] * Flag[37] ^ Flag[24] * Flag[18]) ^ Flag[25]) & Flag[19]) == 100)

# Constraint 5
s.add((bRam0 ^ Flag[28]) == 0x17)

# Constraint 6
s.add((Flag[34] & Flag[16]) == 0x52)

# Constraint 7
s.add((Flag[22] & Flag[29]) == 0x30)

# Constraint 8
s.add((Flag[5] | Flag[14]) == 0x77)

# Constraint 9
s.add((Flag[7] & Flag[17]) == 0x61)

# Constraint 10
s.add(Flag[40] - Flag[9] == 0x18)

# Constraint 11
s.add(Flag[11] * Flag[32] - Flag[23] == 0x2d31)

# Constraint 12
s.add((Flag[26] & (Flag[21] ^ Flag[6])) == 0)

# Constraint 13
s.add(((Flag[39] & Flag[20]) ^ Flag[10]) == 0x56)

# Constraint 14
s.add((Flag[35] & (Flag[40] | (Flag[19] - Flag[9] & Flag[27]) * Flag[38])) == 0x20)

# Constraint 15
s.add((bRam1 & Flag[41]) == 0x21)

# Constraint 16
s.add((Flag[24] + Flag[34] * Flag[22] * Flag[14] - (Flag[29] ^ Flag[23]) & Flag[13]) == 0x10)

# Constraint 17
s.add((Flag[5] ^ Flag[17] - (Flag[30] + (Flag[33] + Flag[18] + Flag[36] ^ Flag[25]))) == 0xfffffe08)

# Constraint 18
s.add((Flag[32] & Flag[42]) * Flag[4] - (Flag[3] - Flag[8]) == 0x2480)

# Constraint 19
s.add(Flag[15] - bRam0 * Flag[37] == -0x2516)

# Constraint 20
s.add(Flag[12] + bRam2 == 0xd8)

# Constraint 21
s.add(Flag[7] - Flag[11] == -8)

# Constraint 22
s.add(((Flag[16] | Flag[28]) & (Flag[31] ^ Flag[13])) == 1)

# Constraint 23
s.add((Flag[37] - Flag[24] & Flag[38]) == 0)

# Constraint 24
s.add(Flag[23] * Flag[12] == 0x35ec)

# Constraint 25
s.add((Flag[42] & bRam2) == 0x61)

# Constraint 26
s.add(Flag[25] - Flag[32] == 0x14)

# Constraint 27
s.add((Flag[30] ^ (Flag[5] & Flag[17])) == 0x13)

# Constraint 28
s.add((Flag[18] | Flag[6]) == 0x7e)

# Constraint 29
s.add((Flag[16] | Flag[22]) == 0x7f)

# Constraint 30
s.add((Flag[29] ^ (Flag[14] * Flag[3] | bRam1)) == 0x344e)

# Constraint 31
s.add(((Flag[10] + Flag[7]) * Flag[31] ^ Flag[33]) == 0x2679)

# Constraint 32
s.add((Flag[34] - (Flag[8] & Flag[11]) + Flag[39] & Flag[36]) == 0x5f)

# Constraint 33
s.add(((Flag[28] + (Flag[15] ^ Flag[20]) ^ Flag[21]) * Flag[40] & bRam0 & Flag[19]) == 0x60)

# Constraint 34
s.add((Flag[41] ^ Flag[9]) == 0x75)

# Constraint 35
s.add(Flag[26] * Flag[35] - (Flag[4] - Flag[27]) == 0x997)

# Constraint 36
s.add((Flag[37] & Flag[22]) * bRam0 == 0xc20)

# Constraint 37
s.add((Flag[3] & Flag[10] + Flag[9]) - (Flag[34] | Flag[36]) == -0x6f)

# Constraint 38
s.add(Flag[28] + Flag[24] == 0xd5)

# Constraint 39
s.add((Flag[26] | Flag[39] | Flag[12]) == 0x77)

# Constraint 40
s.add(Flag[6] - Flag[27] == 6)

# Constraint 41
s.add(Flag[42] - Flag[33] == 0x49)

# Constraint 42
s.add((Flag[20] - Flag[7] * (Flag[8] & (Flag[5] ^ Flag[30])) ^ Flag[32] - Flag[41]) == 0xffffff38)

# Constraint 43
s.add(Flag[11] - Flag[29] == 0x48)

# Constraint 44
s.add((Flag[23] & Flag[15]) == 100)

# Constraint 45
s.add((Flag[25] ^ Flag[35]) == 0x40)

# Constraint 46
s.add(Flag[4] - Flag[13] == 0x31)

# Constraint 47
s.add(Flag[21] + Flag[14] == 0xe6)

# Constraint 48
s.add(((Flag[18] | ((Flag[19] ^ Flag[17]) ^ Flag[16]) + Flag[40]) - Flag[38] ^ bRam2) == 0xdf)

# Constraint 49
s.add(Flag[31] - bRam1 == -0x38)

# Constraint 50
s.add((Flag[36] | Flag[3]) == 0x7f)

# Constraint 51
s.add(Flag[42] * (Flag[20] | Flag[12] - Flag[10] + Flag[25]) == 0x7c83)

# Constraint 52
s.add((Flag[27] - (Flag[32] - (Flag[22] - Flag[5])) | Flag[6]) == 0xfffffffe)

# Constraint 53
s.add(Flag[14] + Flag[4] * Flag[31] == 0x155c)

# Constraint 54
s.add((Flag[34] & bRam0) * (Flag[8] & Flag[9] + bRam1) - Flag[11] == 0x17e5)

# Constraint 55
s.add(Flag[24] * Flag[39] == 0x11d0)

# Constraint 56
s.add(Flag[28] * Flag[15] == 0x323e)

# Constraint 57
s.add((Flag[40] ^ Flag[41] ^ Flag[17] + Flag[30] ^ Flag[37] - (Flag[16] ^ Flag[33]) ^ ((Flag[18] & Flag[21]) ^ Flag[7])) + Flag[23] == -0x15)

# Constraint 58
s.add(Flag[35] + Flag[26] == 99)

# Constraint 59
s.add(Flag[13] * bRam2 * Flag[29] * Flag[38] == 0xbc6940)

# Constraint 60 (final check)
s.add(Flag[19] + (Flag[11] ^ (Flag[4] * Flag[5] & Flag[8]) ^ Flag[30]) == 0x6c)

print("Solving constraints...")
if s.check() == sat:
    print("Solution found")
    m = s.model()
    
    # Extract flag characters
    flag_bytes = []
    for i in range(43):
        val = m[Flag[i]].as_long()
        flag_bytes.append(val)
    
    # Print the flag
    flag_string = ''.join(chr(b) for b in flag_bytes)
    print(f"\nFlag: {flag_string}")
    print(f"\nFlag bytes: {flag_bytes}")
    
    # Print bRam values for reference
    print(f"\nbRam0: {m[bRam0].as_long()}")
    print(f"bRam1: {m[bRam1].as_long()}")
    print(f"bRam2: {m[bRam2].as_long()}")
else:
    print("No solution found")
