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
