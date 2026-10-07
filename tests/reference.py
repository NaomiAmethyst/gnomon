#!/usr/bin/env python3
"""Independent RFC 10049 implementation for fixtures and interoperability tests.
Uses Python cryptography/OpenSSL, not Gnomon's Rust codec or crypto library.
Test-only seeds below must never be deployed.
"""
import argparse
import base64
import hashlib
import json
import os
import pathlib
import socket
import struct
import subprocess
import tempfile
import threading
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = pathlib.Path(__file__).resolve().parents[1]
DELEGATION = b"Roughtime v1 delegation signature\0"
RESPONSE = b"Roughtime v1 response signature\0"

def h(*parts):
    return hashlib.sha512(b"".join(parts)).digest()[:32]

def u32(n):
    return struct.pack("<I", n)

def u64(n):
    return struct.pack("<Q", n)

def public(key):
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

def b64(data):
    return base64.b64encode(data).decode()

def encode(fields):
    fields = sorted(((k.ljust(4,b"\0"),v) for k,v in fields.items()), key=lambda item:struct.unpack("<I",item[0])[0])
    offset = 0
    offsets = []
    for _, value in fields[:-1]:
        offset += len(value)
        assert offset % 4 == 0
        offsets.append(u32(offset))
    return u32(len(fields)) + b"".join(offsets) + b"".join(t for t,_ in fields) + b"".join(v for _,v in fields)

def decode(data):
    n = struct.unpack("<I",data[:4])[0]
    offsets = [0] + [struct.unpack("<I",data[4+4*i:8+4*i])[0] for i in range(n-1)] + [len(data)-8*n]
    return {data[4*n+4*i:4*n+4*i+4].rstrip(b"\0"):data[8*n+offsets[i]:8*n+offsets[i+1]] for i in range(n)}

def packet(message):
    return b"ROUGHTIM" + u32(len(message)) + message

def unpack(p):
    assert p[:8] == b"ROUGHTIM" and struct.unpack("<I",p[8:12])[0] == len(p)-12
    return decode(p[12:])

def request(root, nonce):
    return packet(encode({b"VER":u32(1), b"TYPE":u32(0), b"SRV":h(b"\xff",root), b"NONC":nonce, b"ZZZZ":bytes(912)}))

def certificate(root, online, mint, maxt):
    dele = encode({b"PUBK":public(online), b"MINT":u64(mint), b"MAXT":u64(maxt)})
    return encode({b"SIG":root.sign(DELEGATION+dele), b"DELE":dele})

def response(req, root, online, midpoint):
    srep = encode({b"VER":u32(1), b"VERS":u32(1), b"RADI":u32(3), b"MIDP":u64(midpoint), b"ROOT":h(b"\0",req)})
    return packet(encode({b"TYPE":u32(1), b"NONC":unpack(req)[b"NONC"], b"INDX":u32(0), b"PATH":b"", b"SIG":online.sign(RESPONSE+srep), b"SREP":srep, b"CERT":certificate(root,online,0,2**64-1)}))

def verify(req, resp, root):
    m = unpack(resp)
    assert m[b"TYPE"] == u32(1) and m[b"NONC"] == unpack(req)[b"NONC"]
    c = decode(m[b"CERT"])
    Ed25519PublicKey.from_public_bytes(root).verify(c[b"SIG"],DELEGATION+c[b"DELE"])
    dele = decode(c[b"DELE"])
    Ed25519PublicKey.from_public_bytes(dele[b"PUBK"]).verify(m[b"SIG"],RESPONSE+m[b"SREP"])
    s = decode(m[b"SREP"])
    midpoint = struct.unpack("<Q",s[b"MIDP"])[0]
    assert struct.unpack("<Q",dele[b"MINT"])[0] <= midpoint <= struct.unpack("<Q",dele[b"MAXT"])[0]
    assert s[b"VER"] == u32(1) and s[b"VERS"] == u32(1)
    assert struct.unpack("<I",s[b"RADI"])[0] > 0
    node = h(b"\0",req)
    index = struct.unpack("<I",m[b"INDX"])[0]
    path = m[b"PATH"]
    assert len(path)%32 == 0 and len(path) <= 1024
    for offset in range(0,len(path),32):
        sibling = path[offset:offset+32]
        node = h(b"\1",node,sibling) if index%2 == 0 else h(b"\1",sibling,node)
        index >>= 1
    assert index == 0 and node == s[b"ROOT"]
    return midpoint

def fixture():
    entries = []
    previous = None
    for i,midpoint in enumerate((1000,900,900)):
        root = Ed25519PrivateKey.from_private_bytes(bytes([10+i])*32)
        online = Ed25519PrivateKey.from_private_bytes(bytes([20+i])*32)
        rand = bytes([30+i])*32
        req = request(public(root),h(previous,rand) if previous else rand)
        resp = response(req,root,online,midpoint)
        assert verify(req,resp,public(root)) == midpoint
        entry = {"publicKey":b64(public(root)), "request":b64(req), "response":b64(resp)}
        if previous:
            entry["rand"] = b64(rand)
        entries.append(entry)
        previous = resp
    return {"responses":entries}

def recv_frame(stream):
    def read_exact(n):
        result = b""
        while len(result) < n:
            chunk = stream.recv(n-len(result))
            if not chunk:
                raise RuntimeError("unexpected TCP EOF")
            result += chunk
        return result
    header = read_exact(12)
    return header+read_exact(struct.unpack("<I",header[8:])[0])

def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1",0))
        return sock.getsockname()[1]

def expiry(binaries, tmp):
    """The daemon must stop, not keep accepting work, once its delegation expires."""
    root = Ed25519PrivateKey.from_private_bytes(bytes([60])*32)
    online_seed = bytes([61])*32
    online = Ed25519PrivateKey.from_private_bytes(online_seed)
    folder = tmp / "expiry"
    folder.mkdir()
    (folder / "online.key").write_bytes(online_seed)
    (folder / "online.key").chmod(0o600)
    now = int(time.time())
    (folder / "delegation.cert").write_bytes(certificate(root,online,now-60,now+2))
    port = free_port()
    (folder / "gnomon.toml").write_text(f'listen = "127.0.0.1:{port}"\nonline_key = "{folder}/online.key"\ncertificate = "{folder}/delegation.cert"\nroot_public_key = "{b64(public(root))}"\nrequire_synchronized_clock = false\n')
    with (folder / "daemon.log").open("w") as log:
        proc = subprocess.Popen([str(binaries / "gnomond"),"--config",str(folder / "gnomon.toml")],stdout=log,stderr=log)
    try:
        time.sleep(3.5)
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
            sock.sendto(request(public(root),os.urandom(32)),("127.0.0.1",port))
        assert proc.wait(timeout=5) != 0, "daemon kept running with an expired delegation"
        assert "delegation expired" in (folder / "daemon.log").read_text()
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()

def malfeasance(binaries, tmp):
    """A lying server must produce saved, verifiable evidence."""
    servers, sockets = [], []
    try:
        for i,midpoint in enumerate((2000,1000,1000)):
            root = Ed25519PrivateKey.from_private_bytes(bytes([70+i])*32)
            online = Ed25519PrivateKey.from_private_bytes(bytes([80+i])*32)
            sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            sock.bind(("127.0.0.1",0))
            sockets.append(sock)
            def serve(sock=sock, root=root, online=online, midpoint=midpoint):
                while True:
                    try:
                        req, peer = sock.recvfrom(4096)
                    except OSError:
                        return
                    sock.sendto(response(req,root,online,midpoint),peer)
            threading.Thread(target=serve,daemon=True).start()
            servers.append({"name":f"liar-{i}","version":1,"publicKeyType":"ed25519","publicKey":b64(public(root)),"addresses":[{"protocol":"udp","address":f"127.0.0.1:{sock.getsockname()[1]}"}]})
        (tmp / "liars.json").write_text(json.dumps({"servers":servers}))
        # Order is random, but each server is queried twice, so a 1000 response
        # always follows the 2000 one.
        result = subprocess.run([str(binaries / "gnomon"),"measure","--servers",str(tmp / "liars.json"),"--evidence",str(tmp / "malfeasance.json")],capture_output=True,text=True)
        assert result.returncode != 0 and "causal inconsistency" in result.stderr, result.stderr
        verified = subprocess.run([str(binaries / "gnomon"),"verify-evidence",str(tmp / "malfeasance.json")],check=True,capture_output=True,text=True)
        assert json.loads(verified.stdout)["causalInconsistency"] is not None
    finally:
        for sock in sockets:
            sock.close()

def smoke(binaries, docker_image=None, docker_sudo=False):
    servers, processes = [], []
    docker = ["sudo", "-n", "docker"] if docker_sudo else ["docker"]
    with tempfile.TemporaryDirectory(prefix="gnomon-smoke-") as tmp:
        tmp = pathlib.Path(tmp)
        try:
            for i in range(3):
                root = Ed25519PrivateKey.from_private_bytes(bytes([40+i])*32)
                online_seed = bytes([50+i])*32
                online = Ed25519PrivateKey.from_private_bytes(online_seed)
                folder = tmp / str(i)
                folder.mkdir()
                (folder / "online.key").write_bytes(online_seed)
                (folder / "online.key").chmod(0o600)
                now = int(time.time())
                (folder / "delegation.cert").write_bytes(certificate(root,online,now-60,now+3600))
                port = free_port()
                if docker_image:
                    # Containers are configured only through the environment.
                    name = f"gnomon-smoke-{os.getpid()}-{i}"
                    env = {"GNOMON_LISTEN":f"0.0.0.0:{port}","GNOMON_ROOT_PUBLIC_KEY":b64(public(root)),"GNOMON_REQUIRE_SYNCHRONIZED_CLOCK":"false"}
                    subprocess.run(docker+["run","--detach","--name",name,"--network","host","--read-only","--cap-drop","ALL","--security-opt","no-new-privileges","--user",f"{os.getuid()}:{os.getgid()}","--mount",f"type=bind,src={folder},dst=/etc/gnomon,readonly"]+[a for k,v in env.items() for a in ("--env",f"{k}={v}")]+[docker_image],check=True,stdout=subprocess.DEVNULL)
                    processes.append(name)
                else:
                    (folder / "gnomon.toml").write_text(f'listen = "0.0.0.0:{port}"\nonline_key = "{folder}/online.key"\ncertificate = "{folder}/delegation.cert"\nroot_public_key = "{b64(public(root))}"\nrequire_synchronized_clock = false\n')
                    log = (folder / "daemon.log").open("w")
                    processes.append(subprocess.Popen([str(binaries / "gnomond"),"--config",str(folder / "gnomon.toml")],stdout=log,stderr=log))
                    log.close()
                addr = f"127.0.0.1:{port}"
                key = public(root)
                servers.append({"name":f"local-{i}","version":1,"publicKeyType":"ed25519","publicKey":b64(key),"addresses":[{"protocol":p,"address":addr} for p in ("udp","tcp")]})
                deadline = time.monotonic()+10
                while True:
                    try:
                        with socket.create_connection(("127.0.0.1",port),timeout=.1):
                            break
                    except OSError:
                        if time.monotonic() > deadline:
                            raise RuntimeError(f"daemon did not become ready: {folder}")
                        time.sleep(.05)
                req = request(key,os.urandom(32))
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
                    sock.settimeout(2)
                    sock.sendto(req,("127.0.0.1",port))
                    resp = sock.recv(4096)
                    verify(req,resp,key)
                    assert len(resp) <= len(req)
                    sock.settimeout(.15)
                    for malformed in (b"invalid",req[:200],req+b"\0"):
                        sock.sendto(malformed,("127.0.0.1",port))
                        try:
                            sock.recv(4096)
                            raise AssertionError("response to malformed or short request")
                        except socket.timeout:
                            pass
                with socket.create_connection(("127.0.0.1",port),timeout=2) as stream:
                    stream.sendall(req[:7])
                    stream.sendall(req[7:]+req)
                    verify(req,recv_frame(stream),key)
                    verify(req,recv_frame(stream),key)
                for mode in ("udp","tcp"):
                    subprocess.run([str(binaries / "gnomon"),"query","--server",addr,"--public-key",b64(key),"--transport",mode,"--attempts","1"],check=True,stdout=subprocess.DEVNULL)
            (tmp / "servers.json").write_text(json.dumps({"servers":servers}))
            subprocess.run([str(binaries / "gnomon"),"measure","--servers",str(tmp / "servers.json"),"--evidence",str(tmp / "evidence.json")],check=True)
            subprocess.run([str(binaries / "gnomon"),"verify-evidence",str(tmp / "evidence.json")],check=True)
            entries = json.loads((tmp / "evidence.json").read_text())["responses"]
            assert len(entries) == 6
            prev = None
            for e in entries:
                req,resp,key = (base64.b64decode(e[k]) for k in ("request","response","publicKey"))
                if prev:
                    assert unpack(req)[b"NONC"] == h(prev,base64.b64decode(e["rand"]))
                verify(req,resp,key)
                prev = resp
            before = (tmp / "evidence.json").read_bytes()
            started = time.monotonic()
            again = subprocess.run([str(binaries / "gnomon"),"measure","--servers",str(tmp / "servers.json"),"--evidence",str(tmp / "evidence.json")],capture_output=True)
            assert again.returncode != 0 and time.monotonic()-started < 2, "existing evidence must be refused before querying"
            assert (tmp / "evidence.json").read_bytes() == before
            unreachable = [dict(s,addresses=[{"protocol":"tcp","address":f"127.0.0.1:{free_port()}"}]) for s in servers]
            (tmp / "unreachable.json").write_text(json.dumps({"servers":unreachable}))
            failed = subprocess.run([str(binaries / "gnomon"),"measure","--servers",str(tmp / "unreachable.json"),"--evidence",str(tmp / "unused.json"),"--attempts","1","--timeout-seconds","1"],capture_output=True)
            assert failed.returncode != 0 and not (tmp / "unused.json").exists(), "failed measurement must not leave an evidence file"
            malfeasance(binaries,tmp)
            if not docker_image:
                expiry(binaries,tmp)
            print("Independent UDP/TCP, fragmentation, pipelining, malformed-packet, client, six-response chain, evidence-file, malfeasance, and delegation-expiry checks passed")
        finally:
            for proc in processes:
                if isinstance(proc,str):
                    subprocess.run(docker+["rm","-f",proc],check=True,stdout=subprocess.DEVNULL)
                else:
                    proc.terminate()
            for proc in processes:
                if not isinstance(proc,str):
                    assert proc.wait(timeout=10) == 0, "daemon did not shut down cleanly"

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-fixture",action="store_true")
    parser.add_argument("--binaries",type=pathlib.Path,default=ROOT / "target/debug")
    parser.add_argument("--docker-image")
    parser.add_argument("--docker-sudo",action="store_true")
    args = parser.parse_args()
    if args.write_fixture:
        (ROOT / "tests/fixtures/reference-v1.json").write_text(json.dumps(fixture(),indent=2)+"\n")
    else:
        smoke(args.binaries.resolve(),args.docker_image,args.docker_sudo)
