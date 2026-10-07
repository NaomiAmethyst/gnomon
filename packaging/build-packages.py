#!/usr/bin/env python3
"""Build native .deb, .rpm, and portable tarballs from prebuilt static binaries."""
import argparse
import hashlib
import pathlib
import shutil
import subprocess
import struct
import tarfile
import tempfile
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
MAINTAINER = "Naomi Persephone Amethyst <naomi@amethyst.name>"

def run(*args):
    subprocess.run(args, check=True)

def stage(tree, binaries):
    for name in ("gnomon", "gnomond"):
        dest = tree / "usr/bin" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(binaries / name, dest)
        dest.chmod(0o755)
    for source, target in (
        ("packaging/gnomon.service", "usr/lib/systemd/system/gnomon.service"),
        ("packaging/gnomon.toml.example", "etc/gnomon/gnomon.toml"),
        ("LICENSE", "usr/share/doc/gnomon/copyright"),
        ("README.md", "usr/share/doc/gnomon/README.md"),
        ("NOTICE", "usr/share/doc/gnomon/NOTICE"),
        ("tests/fixtures/LICENSE-RFC", "usr/share/doc/gnomon/LICENSE-RFC"),
        ("THIRD-PARTY-NOTICES", "usr/share/doc/gnomon/THIRD-PARTY-NOTICES"),
    ):
        dest = tree / target
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / source, dest)
        dest.chmod(0o644)
    shutil.copytree(ROOT / "docs", tree / "usr/share/doc/gnomon/docs")

def validate_binaries(binaries, arch):
    for name in ("gnomon", "gnomond"):
        data = (binaries / name).read_bytes()
        if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01":
            raise ValueError(name + " must be a 64-bit little-endian ELF executable")
        kind, machine = struct.unpack_from("<HH", data, 16)
        if kind not in (2, 3) or machine != {"amd64":62, "arm64":183}[arch]:
            raise ValueError(name + " has the wrong ELF architecture or executable type")
        offset = struct.unpack_from("<Q", data, 32)[0]
        entry_size, count = struct.unpack_from("<HH", data, 54)
        if entry_size < 56 or count == 0 or offset + entry_size*count > len(data):
            raise ValueError(name + " has invalid program headers")
        if any(struct.unpack_from("<I", data, offset+i*entry_size)[0] == 3 for i in range(count)):
            raise ValueError(name + " must be statically linked (no ELF interpreter)")

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--binaries", required=True, type=pathlib.Path)
    p.add_argument("--arch", choices=("amd64", "arm64"), required=True)
    p.add_argument("--out", type=pathlib.Path, default=ROOT / "dist")
    p.add_argument("--format", choices=("all", "deb", "rpm", "tar"), default="all")
    args = p.parse_args()
    validate_binaries(args.binaries, args.arch)
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]["version"]
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="gnomon-package-") as tmp:
        tmp = pathlib.Path(tmp)
        tree = tmp / "tree"
        stage(tree, args.binaries.resolve())
        if args.format in ("all", "tar"):
            with tarfile.open(out / f"gnomon-{version}-linux-{args.arch}.tar.gz", "w:gz") as tar:
                for file in sorted(tree.rglob("*")):
                    tar.add(file, arcname=str(file.relative_to(tree)), recursive=False)
        if args.format in ("all", "deb"):
            control = tree / "DEBIAN"
            control.mkdir()
            (control / "control").write_text(f"Package: gnomon\nVersion: {version}\nArchitecture: {args.arch}\nMaintainer: {MAINTAINER}\nSection: net\nPriority: optional\nRecommends: systemd (>= 247)\nHomepage: https://github.com/NaomiAmethyst/gnomon\nDescription: authenticated RFC 10049 Roughtime daemon and client\n Offline delegation, UDP/TCP, Merkle batching, and verifiable evidence.\n")
            (control / "conffiles").write_text("/etc/gnomon/gnomon.toml\n")
            for name, script in {
                "postinst": 'if command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload || true; fi',
                "prerm": 'if [ "$1" = remove ] && command -v systemctl >/dev/null 2>&1; then systemctl stop gnomon.service || true; fi',
                "postrm": 'if command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload || true; fi',
            }.items():
                (control / name).write_text("#!/bin/sh\nset -e\n" + script + "\nexit 0\n")
                (control / name).chmod(0o755)
            run("dpkg-deb", "--root-owner-group", "--build", str(tree), str(out / f"gnomon_{version}_{args.arch}.deb"))
            shutil.rmtree(control)
        if args.format in ("all", "rpm"):
            top = tmp / "rpm"
            for folder in ("BUILD", "BUILDROOT", "RPMS", "SOURCES", "SPECS", "SRPMS"):
                (top / folder).mkdir(parents=True)
            rpmarch = {"amd64": "x86_64", "arm64": "aarch64"}[args.arch]
            with tarfile.open(top / "SOURCES/payload.tar.gz", "w:gz") as tar:
                tar.add(tree, arcname=".")
            spec = top / "SPECS/gnomon.spec"
            spec.write_text(f'''Name: gnomon
Version: {version}
Release: 1
Summary: RFC 10049 Roughtime daemon and client
License: AGPL-3.0-only
URL: https://github.com/NaomiAmethyst/gnomon
Source0: payload.tar.gz
BuildArch: {rpmarch}
AutoReqProv: no
%global debug_package %{{nil}}
%global __os_install_post %{{nil}}
%description
Authenticated rough time with offline key delegation and evidence verification.
%prep
%build
%install
mkdir -p %{{buildroot}}
tar -xzf %{{SOURCE0}} -C %{{buildroot}}
%post
if command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload || :; fi
%preun
if [ "$1" -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
  systemctl stop gnomon.service || :
fi
%postun
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || :
  if [ "$1" -ge 1 ]; then systemctl try-restart gnomon.service || :; fi
fi
%files
%defattr(-,root,root,-)
/usr/bin/gnomon
/usr/bin/gnomond
/usr/lib/systemd/system/gnomon.service
%dir /etc/gnomon
%config(noreplace) /etc/gnomon/gnomon.toml
%doc /usr/share/doc/gnomon
''')
            (top / "database").mkdir()
            run("rpmbuild", "--define", f"_topdir {top}", "--define", f"_dbpath {top / 'database'}", "--target", rpmarch, "-bb", str(spec))
            for file in (top / "RPMS").rglob("*.rpm"):
                shutil.copy2(file, out / file.name)
    with (out / f"SHA256SUMS-{args.arch}").open("w") as sums:
        for f in sorted(out.iterdir()):
            if f.is_file() and not f.name.startswith("SHA256SUMS"):
                sums.write(hashlib.sha256(f.read_bytes()).hexdigest() + "  " + f.name + "\n")

if __name__ == "__main__":
    main()
