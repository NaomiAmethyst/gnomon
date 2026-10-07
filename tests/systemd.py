#!/usr/bin/env python3
"""Exercise the packaged sandbox and systemd credentials in collected transient units."""
import argparse
import os
import pathlib
import shutil
import subprocess
import tempfile
import time
import reference as r

ROOT = pathlib.Path(__file__).resolve().parents[1]

def properties(folder, name):
    args = ["sudo","-n","systemd-run","--quiet","--wait","--collect","--pipe","--unit="+name,
            "--property=BindReadOnlyPaths="+str(folder)+":/opt/gnomon-validation"]
    section = ""
    for line in (ROOT / "packaging/gnomon.service").read_text().splitlines():
        if line.startswith("["):
            section = line
        if section != "[Service]" or "=" not in line or line.startswith("#"):
            continue
        key,value = line.split("=",1)
        if key in ("ExecStart","Restart","RestartSec","TimeoutStopSec","Type"):
            continue
        if key == "LoadCredential":
            value = "online.key:"+str(folder / "online.key")
        args.append("--property="+key+"="+value)
    return args

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binaries",type=pathlib.Path,default=ROOT / "target/debug")
    parser.add_argument("--clock-required",action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="gnomon-systemd-") as tmp:
        folder = pathlib.Path(tmp)
        folder.chmod(0o755)
        shutil.copy2(args.binaries / "gnomond",folder / "gnomond")
        root = r.Ed25519PrivateKey.from_private_bytes(bytes([70])*32)
        online = r.Ed25519PrivateKey.from_private_bytes(bytes([71])*32)
        (folder / "online.key").write_bytes(bytes([71])*32)
        (folder / "online.key").chmod(0o600)
        now = int(time.time())
        (folder / "delegation.cert").write_bytes(r.certificate(root,online,now-60,now+3600))
        (folder / "gnomon.toml").write_text('online_key = "/unavailable-directly/online.key"\ncertificate = "/opt/gnomon-validation/delegation.cert"\nroot_public_key = "'+r.b64(r.public(root))+'"\nrequire_synchronized_clock = '+str(args.clock_required).lower()+'\n')
        subprocess.run(properties(folder,f"gnomon-credential-test-{os.getpid()}")+["/usr/bin/env","/opt/gnomon-validation/gnomond","--config","/opt/gnomon-validation/gnomon.toml","--check"],check=True)
        # This query must be permitted even on CI hosts whose clock is unsynchronized.
        probe = 'import ctypes; b=ctypes.create_string_buffer(1024); c=ctypes.CDLL(None,use_errno=True); s=c.adjtimex(ctypes.byref(b)); assert s>=0,(s,ctypes.get_errno()); print("read-only adjtimex permitted by sandbox")'
        subprocess.run(properties(folder,f"gnomon-clock-test-{os.getpid()}")+["/usr/bin/python3","-c",probe],check=True)
        print("systemd credentials and complete service sandbox passed")

if __name__ == "__main__":
    main()
