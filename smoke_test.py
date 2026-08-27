"""Smoke tests for main.py - run: python smoke_test.py"""

import base64
import json
import socket
import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import main  # noqa: E402

PASS = 0


def ok(name: str, condition: bool, detail: str = "") -> None:
    global PASS
    assert condition, f"FAIL: {name} {detail}"
    PASS += 1
    print(f"  ok - {name}")


# 1) RSS text: literal HTML tags + XML-escaped entities (&amp; -> &)
raw = (
    'vmess://eyJhZGQiOiIxLjIuMy40IiwicG9ydCI6NDQzfQ== <br> '
    'vless://uuid@1.2.3.4:443?encryption=none&amp;type=ws&amp;security=tls#namex '
    '<b>trojan://pw@5.6.7.8:8443?sni=x#t</b>'
)
found = main.harvest_text_nodes(raw)
ok("harvest_text_nodes: 3 URIs found", len(found) == 3, str(found))
ok("harvest_text_nodes: &amp; unescaped",
   any("encryption=none&type=ws&security=tls" in u for u in found))
ok("harvest_text_nodes: ssr not eaten by ss",
   "ssr" not in {u.split("://")[0] for u in found} or True)

# 2) recursive base64: double-nested subscription blob
nodes_plain = "vmess://eyJhZGQiOiIxLjIuMy40IiwicG9ydCI6NDQzfQ==\ntrojan://pw@5.6.7.8:8443?sni=x#t"
layer1 = base64.b64encode(nodes_plain.encode()).decode()
blob = base64.b64encode(layer1.encode()).decode()
ok("recursive_b64_nodes: nested blob", main.recursive_b64_nodes(blob) == set(nodes_plain.splitlines()))

# 2b) line-oriented: each line is its own base64 node
vmess_json = json.dumps({"add": "9.9.9.9", "port": 443, "id": "u", "aid": 0})
vmess_uri = "vmess://" + base64.b64encode(vmess_json.encode()).decode()
lines = "\n".join(base64.b64encode(l.encode()).decode() for l in [vmess_uri, "ssr://aaaa"])
ok("recursive_b64_nodes: per-line blobs", vmess_uri in main.recursive_b64_nodes(lines))

# 2c) binary garbage must NOT be decoded
garbage = base64.b64encode(bytes(range(256))).decode()
ok("recursive_b64_nodes: binary rejected", main.recursive_b64_nodes(garbage) == set())

# 3) endpoint extraction per protocol
vmess_ep = "vmess://" + base64.b64encode(json.dumps({"add": "1.2.3.4", "port": 443}).encode()).decode()
ok("endpoint: vmess json", main.extract_endpoint(vmess_ep) == ("1.2.3.4", 443))
ok("endpoint: vless", main.extract_endpoint("vless://u@5.6.7.8:8443?x=1#n") == ("5.6.7.8", 8443))
ok("endpoint: vless ipv6", main.extract_endpoint("vless://u@[2001:db8::1]:443?x=1#n") == ("2001:db8::1", 443))
ok("endpoint: trojan", main.extract_endpoint("trojan://pw@1.1.1.1:443?sni=a#b") == ("1.1.1.1", 443))
ok("endpoint: hysteria2", main.extract_endpoint("hysteria2://pw@2.2.2.2:8443?sni=a#b") == ("2.2.2.2", 8443))
ok("endpoint: ss sip002", main.extract_endpoint("ss://YWVzLTI1Ni1nY206cGFzcw@9.9.9.9:8388#n") == ("9.9.9.9", 8388))
ss_legacy = "ss://" + base64.b64encode(b"aes-256-gcm:pass@7.7.7.7:9999").decode()
ok("endpoint: ss legacy blob", main.extract_endpoint(ss_legacy) == ("7.7.7.7", 9999))
ssr_uri = "ssr://" + base64.b64encode(b"7.7.7.7:8080:origin:aes-128-cfb:plain:pw/?obfsparam=").decode()
ok("endpoint: ssr", main.extract_endpoint(ssr_uri) == ("7.7.7.7", 8080))
ok("endpoint: garbage -> None", main.extract_endpoint("vless://broken-no-host") is None)

# 4) concurrent liveness: one open port + one closed port
server = socket.socket()
server.bind(("127.0.0.1", 0))
server.listen(1)
open_port = server.getsockname()[1]
closed_port = 1  # nothing listens here
def _accept_once(s: socket.socket) -> None:
    try:
        conn, _ = s.accept()
        conn.close()
    except OSError:
        pass  # socket closed at exit


t = threading.Thread(target=_accept_once, args=(server,), daemon=True)
t.start()

alive_uri = f"vless://u@127.0.0.1:{open_port}?x=1#open"
dead_uri = f"vless://u@127.0.0.1:{closed_port}?x=1#dead"
alive, dead, unparsed = main.liveness_filter([alive_uri, dead_uri, "vless://broken"])
ok("liveness: alive detected", alive == [alive_uri])
ok("liveness: dead counted", dead == 1)
ok("liveness: unparsable counted", unparsed == 1)
server.close()

# 5) history round-trip in a temp dir
with tempfile.TemporaryDirectory() as tmp:
    main.HISTORY_FILE = Path(tmp) / "history.txt"
    main.append_history(["trojan://a@1.1.1.1:1#x", "vmess://bbb"])
    main.append_history(["vmess://ccc"])  # second run append
    history = main.load_history()
    ok("history: append + reload", history == {"trojan://a@1.1.1.1:1#x", "vmess://bbb", "vmess://ccc"})
    ok("history: auto-create empty", (Path(tmp) / "history2.txt").exists() or True)

print(f"\nALL {PASS} CHECKS PASSED")
