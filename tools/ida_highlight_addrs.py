# Copyright 2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# SPDX-License-Identifier: AGPL-3.0-or-later

import json
from idaapi import *
from idautils import *
from idc import *

print("=====================================")
file = idc.AskFile(0, "*", "Select an address file")


def color_instruction(ea, color):
    idc.SetColor(ea, idc.CIC_ITEM, color)


colors = {}

for line in open(file).readlines():
    addr, color = json.loads(line)
    if not color in colors:
        colors[color] = set()
    colors[color].add(addr)
    color_instruction(addr, color)


def each_funcea():
    for segea in Segments():
        for funcea in Functions(segea, SegEnd(segea)):
            yield funcea


def each_instrea_for_func(funcea):
    for (startea, endea) in Chunks(funcea):
        for head in Heads(startea, endea):
            yield head


def get_covered_bbs(funcea, color):
    instrs_found = 0
    for head in each_instrea_for_func(funcea):
        if head in colors[color]:
            instrs_found += 1
    return instrs_found


funcs = [(addr, get_covered_bbs(addr, 0x76ffff)) for addr in each_funcea()]
funcs = sorted(funcs, key=lambda (a, b): b)
for (addr, bbs) in funcs:
    print
    "%x %d" % (addr, bbs)
