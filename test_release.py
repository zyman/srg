"""Releases must be independent of build path, timestamps and ownership."""
import hashlib
import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('release', ROOT / 'make-release.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def test_reproducible_portable_archive_and_checksum(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outputs = []
            for index in range(2):
                source = root / ('build-' + str(index))
                source.mkdir()
                for name in release.FILES:
                    dest = source / name
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(ROOT / name, dest)
                    import os
                    os.utime(dest, (1000 + index, 2000 + index))
                output = root / ('different-name-' + str(index) + '.tar.gz')
                subprocess.run([sys.executable, str(source / 'make-release.py'), '--output', str(output)], check=True, capture_output=True)
                outputs.append(output.read_bytes())
                self.assertEqual(Path(str(output) + '.sha256').read_text().split()[0], hashlib.sha256(outputs[-1]).hexdigest())
                with tarfile.open(output) as archive:
                    names = archive.getnames()
                    self.assertEqual(names, sorted(set(names)))
                    for entry in archive:
                        self.assertTrue(entry.isfile())
                        self.assertEqual((entry.uid, entry.gid, entry.mtime, entry.uname, entry.gname, entry.pax_headers), (0, 0, 0, '', '', {}))
                        self.assertTrue(entry.name.startswith('srg-' + release.__version__ + '/'))
                repeated = subprocess.run([sys.executable, str(source / 'make-release.py'), '--output', str(output)], capture_output=True)
                self.assertNotEqual(repeated.returncode, 0)
                self.assertEqual(output.read_bytes(), outputs[-1])
            self.assertEqual(*outputs)
