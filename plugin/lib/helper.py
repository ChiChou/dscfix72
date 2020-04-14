import subprocess
import shutil
import sys
from pathlib import Path, WindowsPath


def wslpath(path: WindowsPath):
    return subprocess.check_output(['wsl', 'wslpath', str(path).replace('\\', '\\\\')]).strip().decode()


def invoke(cache: Path):
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
