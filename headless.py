#!/usr/env/bin python3

import subprocess
import os
import sys
import shutil
import shlex
from pathlib import Path, WindowsPath


def wslpath(path: WindowsPath):
    return subprocess.check_output(['wsl', 'wslpath', str(path).replace('\\', '\\\\')]).strip().decode()


def generate_symbols(cache: Path):
    # check helper
    helper = Path(__file__).parent / 'helper' / 'dsc'
    if not helper.exists():
        raise RuntimeError('helper "%s" not found. Please build it first')

    if sys.platform == 'win32':
        if not shutil.which('wsl'):
            raise RuntimeError('WSL not found. Your Windows is not supported')
        subprocess.call(['wsl', str(helper.as_posix()), wslpath(cache)])
    else:
        subprocess.call(str(helper), cache)


def main(cache: Path, module: str):
    generate_symbols(cache)

    _, arch = cache.name.rsplit('_', 1)
    cmd = 'idat64' if 'arm64' in arch else 'idat'
    if not shutil.which(cmd):
        raise RuntimeError('"%s" not found in PATH')

    script = Path(__file__).parent / 'plugin' / 'fix.py'

    env = os.environ.copy()
    env['IDA_DYLD_CACHE_MODULE'] = module
    _, name = module.rsplit('/', 1)
    ret = subprocess.call([
        cmd,
        '-TApple DYLD cache for %s (single module)' % arch,
        '-c',
        '-A',
        # bug: you can't quote the path here. So don't use special chars in the filename
        '-S%s %s' % (script, cache),
        '-o%s.i64' % name,
        '-L%s.log' % name,
        # '-Oobjc:+l',
        str(cache)
    ], env=env)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('cache')
    parser.add_argument('module')
    opt = parser.parse_args()

    main(Path(opt.cache), opt.module)
