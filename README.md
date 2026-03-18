---
title: "Wasm-checker - AmateursCTF 2025"
date: "2026-03-18"
tags: ['Shili','Reverse Engineering', 'AmateursCTF 2025']
summary: "Step-by-step walkthrough of the Wasm Reverse Engineering challenge from AmateursCTF 2025."
authors: ['Shili']
layout: PostLayout
---

## Table of contents
- [Challenge Info](#challenge-info)
- [Challenge Description](#challenge-description)
- [Approach](#approach)
- [Solution](#solution)
- [Takeaways](#takeaways)

---
## Challenge Info

- **Event**: AmateursCTF 2025 
- **Category**: Reverse Engineering
- **Attachment**: [wasm-checker](https://github.com/les-amateurs/AmateursCTF-Public/tree/main/2025/rev/wasm-checker)

---

## Challenge Description

> "its a flag checker"

---

## Approach

1. We have two files, `main.mjs` and `module.wasm`. The `main.mjs` file is a Javascript file that we can open with a text editor, and the `module.wasm` file is a WebAssembly binary module that we need to analyze.

Analyse the file to get more information about it. First, let's check what type of file are we dealing with”:
```bash:Terminal
file module.wasm
```

module.wasm: WebAssembly (wasm) binary module version 0x1 (MVP) - "The file is a WebAssembly (wasm) binary module, which is a low-level binary format designed for efficient execution in web browsers and other environments that support WebAssembly. The version 0x1 (MVP) indicates that it is the initial version of the WebAssembly specification, known as the Minimum Viable Product (MVP)." [Source](https://dev.to/bytehackr/understanding-webassembly-wasm-binary-modules-5h8)

Then we check for strings to quickly find any readable ASCII or UTF-8 text inside the binary:
```bash:Terminal
strings module.wasm

memory
check
lkqA
jrrkA
kkrA
qA-G
lslA
qA0G
qA&-
lrqA G
qA!G
lljA
jA$-
sjksA
kAxG
kA&-
lA!-
qA'-
jkA$-
sA(-
jqA"-
sqlkA -
kA1G
sA(-
jrA&-
kAHG
jrlA
kkkA
rA~G
jqlA
jA%-
sksA
ssssA
jAkG
lA&-
ssjA
```
Running strings command reveals that the binary contains a lot of random strings, but if we look at the first two, we can see the words "memory" and "check". We can guess that the program is doing some kind of memory check, and maybe the flag is hidden in the memory. The other strings look like random characters, but they could be obfuscated or encoded data.

The next step is to see what's inside the main.mjs file, as it might give us more information about how the wasm module is being used and what we need to do to find the flag. We can open it with a text editor or use the `cat` command:
```bash:Terminal
nano main.mjs
```

```javascript:main.mjs
import { readFile } from 'fs/promises';
import { createInterface } from 'readline/promises';
import { stdin as input, stdout as output } from "node:process";

const buffer = await readFile("./module.wasm");
const { instance } = await WebAssembly.instantiate(buffer);
const memory = new Uint8Array(instance.exports.memory.buffer);

const rl = createInterface({ input, output });
const flag = (await rl.question("Enter the flag: ")).trim();
rl.close();

for (let i = 0; i < flag.length; i++) {
    memory[i] = flag.charCodeAt(i);
}

if (flag.length === 43 && instance.exports.check()) {
    console.log("nice job!");
} else {
    console.log("nope.");
}
```

As we can see, the program is reading the `module.wasm` file and instantiating it as a WebAssembly module. Then it creates a `Uint8Array` view of the module's memory buffer, which allows us to read and write bytes directly to the module's memory. The program then prompts the user to enter a flag, and it writes the ASCII character codes of the flag into the module's memory. Finally, it checks if the length of the flag is 43 characters and if the `check` function exported by the wasm module returns true. If both conditions are met, it prints "nice job!", otherwise it prints "nope."

2. Decompiling the binary:

We are trying to understand its logic and find where the flag might be hidden. I choose to use [ghidra](https://github.com/nationalsecurityagency/ghidra) for this with a [WebAssembly extension](https://github.com/nneonneo/ghidra-wasm-plugin) that allows it to analyze WebAssembly binaries.

```
undefined4 export::check(void)
{
  if (((((uint)DAT_ram_00000006 + (uint)DAT_ram_00000026) - (uint)DAT_ram_0000001f) -
       ((uint)bRam00000003 &
        (uint)(DAT_ram_00000015 ^ DAT_ram_00000029) -
        (uint)(DAT_ram_0000000c | DAT_ram_0000000d) * (uint)DAT_ram_0000001a |
       (uint)bRam00000002 | (uint)DAT_ram_00000023 + (uint)DAT_ram_00000027) |
      (uint)DAT_ram_00000014 - ((uint)DAT_ram_00000004 - (uint)DAT_ram_0000001e)) != 0x6e) {
    return 0;
  }
  if ((DAT_ram_0000000a | DAT_ram_00000024) != 0x5f) {
    return 0;
  }
  if (((DAT_ram_0000001b ^ DAT_ram_00000008) & DAT_ram_0000000f) != 0x2d) {
    return 0;
  }
  if (((DAT_ram_00000021 ^
       bRam00000001 * (DAT_ram_0000002a * DAT_ram_00000025 ^ DAT_ram_00000018 * DAT_ram_00000012) ^
       DAT_ram_00000019) & DAT_ram_00000013) != 100) {
    return 0;
  }
  if ((bRam00000000 ^ DAT_ram_0000001c) != 0x17) {
    return 0;
  }
  if ((DAT_ram_00000022 & DAT_ram_00000010) != 0x52) {
    return 0;
  }
  if ((DAT_ram_00000016 & DAT_ram_0000001d) != 0x30) {
    return 0;
  }
  if ((DAT_ram_00000005 | DAT_ram_0000000e) != 0x77) {
    return 0;
  }
  if ((DAT_ram_00000007 & DAT_ram_00000011) != 0x61) {
    return 0;
  }
  if ((uint)DAT_ram_00000028 - (uint)DAT_ram_00000009 != 0x18) {
    return 0;
  }
  if ((undefined *)((uint)DAT_ram_0000000b * (uint)DAT_ram_00000020 - (uint)DAT_ram_00000017) !=
      &DAT_ram_00002d31) {
    return 0;
  }
  if ((DAT_ram_0000001a & (DAT_ram_00000015 ^ DAT_ram_00000006)) != 0) {
    return 0;
  }
  if ((byte)(DAT_ram_00000027 & DAT_ram_00000014 ^ DAT_ram_0000000a) != 0x56) {
    return 0;
  }
  if ((DAT_ram_00000023 &
      (DAT_ram_00000028 |
      (DAT_ram_00000013 - DAT_ram_00000009 & DAT_ram_0000001b) * DAT_ram_00000026)) != 0x20) {
    return 0;
  }
  if ((bRam00000001 & DAT_ram_00000029) != 0x21) {
    return 0;
  }
  if (((DAT_ram_00000018 + DAT_ram_00000022 * DAT_ram_00000016 * DAT_ram_0000000e) -
       (DAT_ram_0000001d ^ DAT_ram_00000017) & DAT_ram_0000000d) != 0x10) {
    return 0;
  }
  if (((uint)DAT_ram_00000005 ^
      (uint)DAT_ram_00000011 -
      ((uint)DAT_ram_0000001e +
      ((uint)DAT_ram_00000021 + (uint)DAT_ram_00000012 + (uint)DAT_ram_00000024 ^
      (uint)DAT_ram_00000019))) != 0xfffffe08) {
    return 0;
  }
  if ((undefined *)
      ((uint)(DAT_ram_00000020 & DAT_ram_0000002a) * (uint)DAT_ram_00000004 -
      ((uint)bRam00000003 - (uint)DAT_ram_00000008)) != &DAT_ram_00002480) {
    return 0;
  }
  if ((uint)DAT_ram_0000000f - (uint)bRam00000000 * (uint)DAT_ram_00000025 != -0x2516) {
    return 0;
  }
  if ((uint)DAT_ram_0000000c + (uint)bRam00000002 != 0xd8) {
    return 0;
  }
  if ((uint)DAT_ram_00000007 - (uint)DAT_ram_0000000b != -8) {
    return 0;
  }
  if ((byte)((DAT_ram_00000010 | DAT_ram_0000001c) & (DAT_ram_0000001f ^ DAT_ram_0000000d)) != 1) {
    return 0;
  }
  if ((DAT_ram_00000025 - DAT_ram_00000018 & DAT_ram_00000026) != 0) {
    return 0;
  }
  if ((undefined *)((uint)DAT_ram_00000017 * (uint)DAT_ram_0000000c) != &DAT_ram_000035ec) {
    return 0;
  }
  if ((DAT_ram_0000002a & bRam00000002) != 0x61) {
    return 0;
  }
  if ((uint)DAT_ram_00000019 - (uint)DAT_ram_00000020 != 0x14) {
    return 0;
  }
  if ((byte)(DAT_ram_0000001e ^ DAT_ram_00000005 & DAT_ram_00000011) != 0x13) {
    return 0;
  }
  if ((DAT_ram_00000012 | DAT_ram_00000006) != 0x7e) {
    return 0;
  }
  if ((DAT_ram_00000010 | DAT_ram_00000016) != 0x7f) {
    return 0;
  }
  if ((undefined *)
      ((uint)DAT_ram_0000001d ^ ((uint)DAT_ram_0000000e * (uint)bRam00000003 | (uint)bRam00000001))
      != &DAT_ram_0000344e) {
    return 0;
  }
  if ((undefined *)
      (((uint)DAT_ram_0000000a + (uint)DAT_ram_00000007) * (uint)DAT_ram_0000001f ^
      (uint)DAT_ram_00000021) != &DAT_ram_00002679) {
    return 0;
  }
  if ((DAT_ram_00000022 - ((DAT_ram_00000008 & DAT_ram_0000000b) + DAT_ram_00000027) &
      DAT_ram_00000024) == 0x5f) {
    if ((byte)((DAT_ram_0000001c + (DAT_ram_0000000f ^ DAT_ram_00000014) ^ DAT_ram_00000015) *
               DAT_ram_00000028 & bRam00000000 & DAT_ram_00000013) != 0x60) {
      return 0;
    }
    if ((DAT_ram_00000029 ^ DAT_ram_00000009) != 0x75) {
      return 0;
    }
    if ((uint)DAT_ram_0000001a * (uint)DAT_ram_00000023 -
        ((uint)DAT_ram_00000004 - (uint)DAT_ram_0000001b) != 0x997) {
      return 0;
    }
    if ((uint)(DAT_ram_00000025 & DAT_ram_00000016) * (uint)bRam00000000 != 0xc20) {
      return 0;
    }
    if (((uint)bRam00000003 & (uint)DAT_ram_0000000a + (uint)DAT_ram_00000009) -
        (uint)(DAT_ram_00000022 | DAT_ram_00000024) != -0x6f) {
      return 0;
    }
    if ((uint)DAT_ram_0000001c + (uint)DAT_ram_00000018 != 0xd5) {
      return 0;
    }
    if ((byte)(DAT_ram_0000001a | DAT_ram_00000027 | DAT_ram_0000000c) != 0x77) {
      return 0;
    }
    if ((uint)DAT_ram_00000006 - (uint)DAT_ram_0000001b != 6) {
      return 0;
    }
    if ((uint)DAT_ram_0000002a - (uint)DAT_ram_00000021 != 0x49) {
      return 0;
    }
    if (((uint)DAT_ram_00000014 -
         (uint)DAT_ram_00000007 * (uint)(DAT_ram_00000008 & (DAT_ram_00000005 ^ DAT_ram_0000001e)) ^
        (uint)DAT_ram_00000020 - (uint)DAT_ram_00000029) != 0xffffff38) {
      return 0;
    }
    if ((uint)DAT_ram_0000000b - (uint)DAT_ram_0000001d != 0x48) {
      return 0;
    }
    if ((DAT_ram_00000017 & DAT_ram_0000000f) != 100) {
      return 0;
    }
    if ((DAT_ram_00000019 ^ DAT_ram_00000023) != 0x40) {
      return 0;
    }
    if ((uint)DAT_ram_00000004 - (uint)DAT_ram_0000000d != 0x31) {
      return 0;
    }
    if ((uint)DAT_ram_00000015 + (uint)DAT_ram_0000000e != 0xe6) {
      return 0;
    }
    if ((((uint)DAT_ram_00000012 |
         (uint)(byte)(DAT_ram_00000013 ^ DAT_ram_00000011 ^ DAT_ram_00000010) +
         (uint)DAT_ram_00000028) - (uint)DAT_ram_00000026 ^ (uint)bRam00000002) == 0xdf) {
      if ((uint)DAT_ram_0000001f - (uint)bRam00000001 != -0x38) {
        return 0;
      }
      if ((DAT_ram_00000024 | bRam00000003) != 0x7f) {
        return 0;
      }
      if ((undefined *)
          ((uint)DAT_ram_0000002a *
          ((uint)DAT_ram_00000014 |
          ((uint)DAT_ram_0000000c - (uint)DAT_ram_0000000a) + (uint)DAT_ram_00000019)) !=
          &DAT_ram_00007c83) {
        return 0;
      }
      if (((uint)DAT_ram_0000001b -
           ((uint)DAT_ram_00000020 - ((uint)DAT_ram_00000016 - (uint)DAT_ram_00000005)) |
          (uint)DAT_ram_00000006) != 0xfffffffe) {
        return 0;
      }
      if ((undefined *)((uint)DAT_ram_0000000e + (uint)DAT_ram_00000004 * (uint)DAT_ram_0000001f) !=
          &DAT_ram_0000155c) {
        return 0;
      }
      if ((undefined *)
          ((uint)(DAT_ram_00000022 & bRam00000000) *
           ((uint)DAT_ram_00000008 & (uint)DAT_ram_00000009 + (uint)bRam00000001) -
          (uint)DAT_ram_0000000b) != &DAT_ram_000017e5) {
        return 0;
      }
      if ((undefined *)((uint)DAT_ram_00000018 * (uint)DAT_ram_00000027) != &DAT_ram_000011d0) {
        return 0;
      }
      if ((undefined *)((uint)DAT_ram_0000001c * (uint)DAT_ram_0000000f) == &DAT_ram_0000323e) {
        if (((uint)DAT_ram_00000028 ^
            (uint)DAT_ram_00000029 ^
            (uint)DAT_ram_00000011 + (uint)DAT_ram_0000001e ^
            (uint)DAT_ram_00000025 - (uint)(DAT_ram_00000010 ^ DAT_ram_00000021) ^
            (uint)(byte)(DAT_ram_00000012 & DAT_ram_00000015 ^ DAT_ram_00000007)) +
            (uint)DAT_ram_00000017 != -0x15) {
          return 0;
        }
        if ((uint)DAT_ram_00000023 + (uint)DAT_ram_0000001a != 99) {
          return 0;
        }
        if ((uint)DAT_ram_0000000d *
            (uint)bRam00000002 * (uint)DAT_ram_0000001d * (uint)DAT_ram_00000026 != 0xbc6940) {
          return 0;
        }
        if ((uint)DAT_ram_00000013 +
            ((uint)DAT_ram_0000000b ^
            (uint)DAT_ram_00000004 * (uint)DAT_ram_00000005 & (uint)DAT_ram_00000008 ^
            (uint)DAT_ram_0000001e) == 0x6c) {
          return 1;
        }
        return 0;
      }
      return 0;
    }
    return 0;
  }
  return 0;
}
```

As we can see, the funcion is doing a lot of checks on the values stored in memory. If a check fails, that check returns 0. Also, the places in memory that are being checked are in continuous addresses, which means that they are probably the ones where the flag is stored.
Knowing this and the fact that the `main.mjs` file has a variable called `flag` that has 43 bytes, we can assume that the flag has 43 characters, the flag's hidden in the memory and we need to fulfill each one of these checks to make sure that we have the correct flag.

## Solution

3. By reading the constraints, we can treat them as a system of equations so lets find the flag using an SAT solver. We can use python with the [z3](https://github.com/Z3Prover/z3) library to solve the constraints and find the values that satisfy all the checks:

```python:Python
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
s.add((Flag[6] + Flag[38] - Flag[31] - ((Flag[3] & (Flag[21] ^ Flag[41]) - (Flag[12] | Flag[13]) * Flag[26]) | (bRam2 | Flag[35] + Flag[39])) | Flag[20] - (Flag[4] - Flag[30])) == 0x6e)

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
```

**Explaining this python script:**
1. We create a Z3 solver instance to handle our constraints.
2. We define a 43 byte array `Flag` to represent the characters of the flag, and three additional variables for the bRam values.
3. We add a constraint to ensure that all the flag bytes are printable ASCII characters (between 32 and 126).
4. We add all the constraints/checks from the WASM function as Z3 constraints.
5. We call `s.check()` to see if there is a solution that satisfies all the constraints. If there is, we extract the values of the flag bytes and print the resulting flag string. We also print the individual byte values and the bRam values for reference.
6. If no solution is found, we print a message indicating that. Else, we print the flag that satisfies all the constraints defined in the WASM binary.

When we run this script, it will output the flag that satisfies all the constraints defined in the WASM binary:

**Flag: `amateursCTF{w4sm_and_s4t_s0lv3r5_4r3_c00l!}`**

---

## Takeaways

- Breaking down the problem into smaller steps (analyzing the files, understanding the logic, and then solving the constraints) is crucial in reverse engineering challenges.
- Understanding the underlying logic of a program is essential for effective reverse engineering.
- SAT solvers like Z3 can be incredibly powerful tools for solving complex constraints in reverse engineering.
