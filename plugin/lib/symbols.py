import os
from bisect import bisect_right, insort_left
from collections import namedtuple


Segment = namedtuple(
    'Segment', ['library', 'name', 'base', 'ceil', 'fileoff', 'size', 'perm'])
Section = namedtuple('Section', [
                     'library', 'name', 'section', 'base', 'ceil', 'fileoff', 'size', 'perm'])


class Symbols(object):
    def __init__(self, filename):
        self.filename = filename
        self.symbols = {}

        self.sections = {}
        self.sect_lookup = {}
        self.sect_index = []

        self.segments = {}
        self.seg_lookup = {}
        self.seg_index = []

    def load(self):
        with open(self.filename, 'r', encoding='utf8') as fp:
            path = None
            permission = None
            section_name = None

            for line in fp:
                feed = line.strip().split(' ')
                if line.startswith('file '):
                    _, path = feed
                    continue

                if not path:
                    raise ValueError('invalid file')

                if line.startswith('segment '):
                    _, name, base, ceil, fileoff, size, perm = feed

                    section_name = name
                    permission = perm

                    base = int(base, 16)
                    ceil = int(ceil, 16)
                    fileoff = int(fileoff, 16)
                    size = int(size, 16)
                    seg = Segment(path, name, base, ceil, fileoff, size, perm)

                    if path not in self.segments:
                        self.segments[path] = {}
                        self.sections[path] = {}
                    self.segments[path][name] = seg

                    if name != '__LINKEDIT':
                        insort_left(self.seg_index, base)
                        self.seg_lookup[base] = seg
                    continue

                if line.startswith('section '):
                    _, name, base, ceil, fileoff, size = feed
                    if permission is None or path not in self.sections:
                        raise ValueError('invalid file')

                    base = int(base, 16)
                    ceil = int(ceil, 16)
                    fileoff = int(fileoff, 16)
                    size = int(size, 16)
                    sect = Section(path, name, section_name, base,
                                   ceil, fileoff, size, permission)
                    self.sections[path][name] = sect
                    insort_left(self.sect_index, base)
                    self.sect_lookup[base] = sect
                    continue

                if line.startswith('symbol '):
                    _, name, addr = feed
                    self.symbols[int(addr, 16)] = name
                    continue

                raise ValueError('invalid file, unexpected line %s', line)

    # def fast(self, addr):
    #     i = bisect_right(self.seg_index, addr)
    #     if not i:
    #         raise ValueError
    #     base = self.seg_index[i - 1]
    #     return self.seg_lookup[base]

    # def locate(self, addr):
    #     for segments in self.segments.values():
    #         for segment in segments.values():
    #             _, _, base, ceil, _ = segment
    #             if base <= addr <= ceil:
    #                 return segment

    def fast(self, addr):
        i = bisect_right(self.sect_index, addr)
        if not i:
            raise ValueError
        base = self.sect_index[i - 1]
        sect = self.sect_lookup[base]
        if sect.ceil > addr:
            return sect
        raise StopIteration('not found')

    def locate(self, addr):
        for sections in self.sections.values():
            for sect in sections.values():
                _, _, _, base, ceil, _, _, _ = sect
                if base <= addr <= ceil:
                    return sect

    def lookup(self, addr):
        return self.symbols[addr]


if __name__ == "__main__":
    import sys
    s = Symbols(sys.argv[1])
    s.load()

    print(s.fast(0x1C64209A8))
    print(s.locate(0x1C64209A8))
    print(s.segments['/usr/lib/libobjc.A.dylib']['__OBJC_RO'])
