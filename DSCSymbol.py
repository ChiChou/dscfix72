import os


class DSCSymbol(object):
    def __init__(self, filename):
        self.filename = filename
        self.segments = {}
        self.symbols = {}
        self.base_lookup = {}
        self.base_index = []

    def load(self):
        with open(self.filename, 'r') as fp:
            path = None
            lib = None
            for line in fp:
                feed = line.strip().split(' ')
                if line.startswith('file '):
                    _, path = feed
                    lib = os.path.basename(path)
                    continue

                if not path:
                    raise ValueError('invalid file')

                if line.startswith('segment '):
                    _, name, base, ceil = feed
                    base = int(base, 16)
                    ceil = int(ceil, 16)
                    if path not in self.segments:
                        self.segments[path] = {}
                    self.segments[path][name] = [base, ceil]
                    if name != '__LINKEDIT':
                        self.base_index.append(base)
                        self.base_lookup[base] = [ceil, lib, name]
                        # self.index.append([base, ceil, '%s:%s' % (os.path.basename(lib), name)])
                    continue

                if line.startswith('symbol '):
                    _, name, addr = feed
                    self.symbols[int(addr, 16)] = name
                    continue

                raise ValueError('invalid file, unexpected line %s', line)
        
        # optimzie
        self.base_index = sorted(self.base_index)      

    def fast(self, addr):
        from bisect import bisect_left
        def find_lt():
            i = bisect_left(self.base_index, addr)
            if i:
                return self.base_index[i - 1]
            raise ValueError
        return s.base_lookup[find_lt()]

    def locate(self, addr):
        for filename, item in self.segments.items():
            for segment, therange in item.items():
                base, ceil = therange
                if base <= addr <= ceil:
                    return [filename, segment, base, ceil]

    def lookup(self, addr):
        return self.symbols[addr]


if __name__ == "__main__":
    s = DSCSymbol('/mnt/h/iPhoneX.dyld_shared_cache_arm64.symbol')
    s.load()

    print(s.fast(0x1C64209A8))
    print(s.locate(0x1C64209A8))
