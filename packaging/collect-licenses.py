#!/usr/bin/env python3
"""Collect license texts for the resolved production dependency graph."""
import argparse
import json
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("--out",type=pathlib.Path,default=ROOT / "THIRD-PARTY-NOTICES")
args = parser.parse_args()
meta = json.loads(subprocess.check_output(["cargo","metadata","--locked","--format-version","1","--filter-platform","x86_64-unknown-linux-musl"],cwd=ROOT))
nodes = {n["id"]:n for n in meta["resolve"]["nodes"]}
root = meta["resolve"]["root"]
selected, todo = set(), [root]
while todo:
    identifier = todo.pop()
    if identifier in selected:
        continue
    selected.add(identifier)
    todo.extend(d["pkg"] for d in nodes[identifier]["deps"] if any(k["kind"] != "dev" for k in d["dep_kinds"]))
texts = ["Third-party notices for Gnomon\nGenerated from Cargo.lock by packaging/collect-licenses.py.\nOriginal Gnomon code is AGPL-3.0-only; dependency licenses follow.\n"]
for package in sorted(meta["packages"],key=lambda p:(p["name"],p["version"])):
    if package["id"] not in selected or package["id"] == root:
        continue
    folder = pathlib.Path(package["manifest_path"]).parent
    files = sorted(f for f in folder.iterdir() if f.is_file() and f.name.upper().startswith(("LICENSE","COPYING","NOTICE")))
    texts.append("\n"+"="*72+"\n"+package["name"]+" "+package["version"]+" — "+str(package["license"])+"\nSource: https://crates.io/crates/"+package["name"]+"/"+package["version"]+"\n")
    if not files:
        raise RuntimeError("Missing dependency license texts: "+package["name"])
    for file in files:
        texts.append("\n--- "+file.name+" ---\n"+file.read_text()+"\n")
for name in ("Rust-LICENSE-MIT", "Rust-LICENSE-APACHE", "musl-COPYRIGHT"):
    file = ROOT / "packaging" / name
    if file.exists():
        texts.append("\n"+"="*72+"\n"+name+"\n"+file.read_text()+"\n")
args.out.write_text("\n".join(line.rstrip() for line in "".join(texts).splitlines()).rstrip()+"\n")
