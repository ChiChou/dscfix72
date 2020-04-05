#!/usr/env/bin python3

import subprocess
import os
import sys
import shutil
import shlex
from pathlib import Path, WindowsPath, PosixPath


def wslpath(path: WindowsPath):
    return subprocess.check_output(['wsl', 'wslpath', str(path).replace('\\', '\\\\')]).strip().decode()

def main(cache: Path, module: str):
    # check helper
    helper = Path(__file__).parent / 'helper' / 'dsc' 
    if not helper.exists():
        raise RuntimeError('helper "%s" not found. Please build it first')
    
    if sys.platform == 'win32':
        if not shutil.which('wsl'):
            raise RuntimeError('wsl not found. Your Windows is not supported')
        subprocess.call(['wsl', str(helper.as_posix()), wslpath(cache)])
    else:
        subprocess.call(str(helper), cache)
    
    _, arch = cache.name.rsplit('_', 1)
    cmd = 'idat64' if 'arm64' in arch else 'idat'
    if not shutil.which(cmd):
        raise RuntimeError('"%s" not found in PATH')

    env = os.environ.copy()
    env['IDA_DYLD_CACHE_MODULE'] = module
    _, name = module.rsplit('/', 1)
    ret = subprocess.call([
        cmd,
        '-TApple DYLD cache for %s (single module)' % arch,
        '-c',
        '-A', 
        '-Sdsc_fix.py %s' % str(cache), # bug: you can't quote the path here. So don't use special chars in the filename
        '-o%s.i64' % name,
        '-L%s.log' % name,
        '-Oobjc:+l',
        str(cache)
    ], env=env)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('cache')
    parser.add_argument('module')
    opt = parser.parse_args()

    main(Path(opt.cache), opt.module)
