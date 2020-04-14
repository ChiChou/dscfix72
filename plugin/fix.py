from __future__ import print_function
from lib.symbols import Symbols

import os
import sys

import idc
import idautils
import idaapi
import ida_segment
import ida_bytes
import ida_funcs
import ida_idaapi
import ida_kernwin as kw

from ida_loader import load_and_run_plugin
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))


def dscu_load_module(module):
    node = idaapi.netnode()
    node.create("$ dscu")
    node.supset(2, module)
    load_and_run_plugin("dscu", 1)


def dscu_load_region(ea):
    node = idaapi.netnode()
    node.create("$ dscu")
    node.altset(3, ea)
    load_and_run_plugin("dscu", 2)


def parse_perm(s):
    mapping = {
        'R': idaapi.SEGPERM_READ,
        'W': idaapi.SEGPERM_WRITE,
        'X': idaapi.SEGPERM_EXEC,
    }

    perm = 0
    for ch, value in mapping.items():
        if ch in s:
            perm |= value

    return perm


def uniq_name(name):
    suggested = name
    i = 0
    while idc.get_name_ea_simple(suggested) != idc.BADADDR:
        suggested = '%s%d' % (name, i)
        i += 1
    return suggested


class Task(object):
    def __init__(self, symbols: Symbols, filename):
        self.symbols = symbols
        self.filename = filename

    def fix(self, ea):
        try:
            section = self.symbols.fast(ea)
        except StopIteration:
            # todo: protocols
            print('%x not found' % ea)
            return
        idc.loadfile(self.filename, section.fileoff,
                     section.base, section.size)
        idc.add_segm_ex(section.base, section.ceil, 0, 2, idaapi.saRelPara,
                        idaapi.scPub, idc.ADDSEG_FILLGAP)
        perm = parse_perm(section.perm)
        idc.set_segm_attr(section.base, idc.SEGATTR_PERM, perm)
        if perm & idaapi.SEGPERM_EXEC:
            idc.create_insn(ea)
        sect_name = ':'.join([os.path.basename(section.library), section.name])
        idc.set_segm_name(section.base, sect_name)

    def find_bad_addr(self, ea):
        def unknown_call_target(ea):
            # todo: x86?
            if idc.print_insn_mnem(ea) != 'BL':
                return None

            target = idc.get_operand_value(ea, 0)
            # print('call:', hex(target))
            if idc.get_segm_start(target) == idc.BADADDR:
                return target

        todo = set()
        names = {}
        stubs = set()
        for addr in idautils.Functions():
            func = ida_funcs.get_func(addr)
            curr_ea = func.start_ea
            while curr_ea != idc.BADADDR and curr_ea <= func.end_ea:
                target = unknown_call_target(curr_ea)
                if target:
                    try:
                        sect = self.symbols.fast(target)
                    except StopIteration:
                        print('%x not found', target)
                        continue
                    base = sect.base
                    todo.add(base)

                    if sect.name == '__stubs':
                        stubs.add(target)
                    else:
                        try:
                            names[target] = self.symbols.lookup(target)
                        except KeyError:
                            print('unknown: %x' % target)
                curr_ea = idc.next_head(curr_ea)

        for base in todo:
            self.fix(base)

        for ea, name in names.items():
            idc.set_name(ea, name, idc.SN_CHECK)

        # fix __stubs
        for ea in stubs:
            next_ea = ea + idc.create_insn(ea)
            if idc.print_insn_mnem(ea) == 'ADRL':
                addr = idc.get_operand_value(ea, 1)
            elif idc.print_insn_mnem(ea) == 'ADRP' and idc.print_insn_mnem(next_ea) == 'ADD':
                addr = idc.get_operand_value(
                    ea, 1) + idc.get_operand_value(next_ea, 2)
            else:
                print('unknown instructions at %x' % ea)
                continue

            try:
                name = self.symbols.lookup(addr)
            except KeyError:
                print('warning: %d not found', addr)
                continue

            self.fix(addr)
            suggested = uniq_name('j_' + name)
            print('rename %x to %s' % (ea, suggested))
            idc.set_name(ea, suggested, idc.SN_CHECK)

    def resolve_classes(self, ea):
        end = idc.get_segm_end(ea)
        for addr in range(ea, end, 8):
            p = idc.get_qword(addr)
            if idc.get_segm_start(p) == idc.BADADDR:
                self.fix(p)
            try:
                name = self.symbols.lookup(p)
            except KeyError:
                print('unknown %x' % p)
                continue

            print('rename %x to %s' % (p, name))
            idc.set_name(p, name, idc.SN_CHECK)

    def resolve_selectors(self, ea):
        segment = self.symbols.segments['/usr/lib/libobjc.A.dylib']['__OBJC_RO']
        base = segment.base
        dscu_load_region(base)

        end = idc.get_segm_end(ea)
        for addr in range(ea, end, 8):
            p = idc.get_qword(addr)
            ida_bytes.create_strlit(p, 0, 0)

    def go(self):
        seg = ida_segment.get_first_seg()
        segments = []
        while seg:
            segments.append(seg)
            seg = ida_segment.get_next_seg(seg.start_ea)

        for seg in segments:
            segm_name = ida_segment.get_segm_name(seg)
            if ':' not in segm_name:
                continue
            _, name = segm_name.split(':')
            if name == '__text':
                self.find_bad_addr(seg.start_ea)
            elif name == '__objc_selrefs':
                self.resolve_selectors(seg.start_ea)
            elif name in ('__objc_classrefs', '__objc_protorefs', '__objc_superrefs'):
                self.resolve_classes(seg.start_ea)
            # todo: __cfstring


def main():
    do_not_exit = False
    if len(idc.ARGV) < 2:
        do_not_exit = True
        path = kw.ask_file(0, "*.*", "dyld shared cache")
    else:
        path = idc.ARGV[1]

    dscu_load_module('/usr/lib/libobjc.A.dylib')
    # perform autoanalysis
    idc.auto_mark_range(0, idc.BADADDR, idc.AU_FINAL)
    idc.auto_wait()

    # analyze objc segments
    load_and_run_plugin("objc", 1)
    # analyze NSConcreteGlobalBlock objects
    load_and_run_plugin("objc", 4)

    sym = path + '.symbol'
    if not os.path.exists(sym):
        # todo:
        raise NotImplementedError(
            'you need to manually generate .symbol file with the helper now')

    s = Symbols(sym)
    s.load()
    t = Task(s, path)
    t.go()

    if not do_not_exit:
        idc.qexit(0)


if __name__ == "__main__":
    main()
