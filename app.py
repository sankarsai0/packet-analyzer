import json
import os
import queue
import subprocess
import threading
import time
import uuid
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request, stream_with_context
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER = Path("uploads")
UPLOAD_FOLDER.mkdir(exist_ok=True)

# Server-side cache of raw packet layers, keyed by upload session id.
# This avoids sending megabytes of raw JSON in the initial upload response.
_session_raw: dict[str, list[dict]] = {}
_session_lock = threading.Lock()

# ──────────────────────────────────────────────
# State management for live capture
# ──────────────────────────────────────────────
capture_proc: subprocess.Popen | None = None
capture_lock = threading.Lock()
packet_queue: queue.Queue = queue.Queue(maxsize=2000)


# ──────────────────────────────────────────────
# tshark helpers
# ──────────────────────────────────────────────
def find_tshark() -> str:
    """Return path to tshark. Falls back to common Windows install location."""
    candidates = [
        "tshark",
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
    ]
    for c in candidates:
        try:
            result = subprocess.run(
                [c, "--version"],
                capture_output=True,
                timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            if result.returncode == 0:
                return c
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    raise RuntimeError("tshark not found. Please install Wireshark and ensure tshark is on PATH.")


def parse_tshark_json(raw: str) -> dict | None:
    """Parse a single tshark JSON packet to a simplified dict."""
    try:
        pkt = json.loads(raw)
        layers = pkt.get("_source", {}).get("layers", {})
        frame = layers.get("frame", {})
        ip = layers.get("ip", layers.get("ipv6", {}))
        tcp = layers.get("tcp", {})
        udp = layers.get("udp", {})
        proto_raw = frame.get("frame.protocols", "")
        protocol = _highest_protocol(proto_raw)
        return {
            "number": frame.get("frame.number", ""),
            "time": frame.get("frame.time_relative", frame.get("frame.time", "")),
            "src": ip.get("ip.src", ip.get("ipv6.src", layers.get("eth", {}).get("eth.src", "—"))),
            "dst": ip.get("ip.dst", ip.get("ipv6.dst", layers.get("eth", {}).get("eth.dst", "—"))),
            "protocol": protocol,
            "length": frame.get("frame.len", ""),
            "info": _build_info(protocol, layers),
            "raw": layers,
        }
    except (json.JSONDecodeError, AttributeError):
        return None


def _highest_protocol(chain: str) -> str:
    """Pick the highest-level protocol from the tshark protocol chain string."""
    priority = [
        "http2", "http", "tls", "ssl",
        "dns", "dhcp", "bootp",
        "tcp", "udp", "icmp", "icmpv6",
        "arp", "ipv6", "ip", "eth",
    ]
    parts = chain.lower().split(":")
    for p in priority:
        if p in parts:
            return p.upper()
    return parts[-1].upper() if parts else "UNKNOWN"


def _build_info(protocol: str, layers: dict) -> str:
    """Build a human-readable info string."""
    try:
        if protocol == "HTTP":
            http = layers.get("http", {})
            return http.get("http.request.full_uri", http.get("http.response.code", ""))
        if protocol == "DNS":
            dns = layers.get("dns", {})
            return dns.get("dns.qry.name", dns.get("dns.resp.name", ""))
        if protocol in ("TCP", "HTTP", "TLS", "SSL"):
            tcp = layers.get("tcp", {})
            flags = tcp.get("tcp.flags_tree", {})
            flag_names = []
            if flags.get("tcp.flags.syn") == "1":
                flag_names.append("SYN")
            if flags.get("tcp.flags.ack") == "1":
                flag_names.append("ACK")
            if flags.get("tcp.flags.fin") == "1":
                flag_names.append("FIN")
            if flags.get("tcp.flags.rst") == "1":
                flag_names.append("RST")
            sport = tcp.get("tcp.srcport", "")
            dport = tcp.get("tcp.dstport", "")
            flags_str = " ".join(flag_names) if flag_names else ""
            return f"{sport} → {dport} [{flags_str}]"
        if protocol == "UDP":
            udp = layers.get("udp", {})
            return f"{udp.get('udp.srcport', '')} → {udp.get('udp.dstport', '')}"
        if protocol == "ARP":
            arp = layers.get("arp", {})
            return f"Who has {arp.get('arp.dst.proto_ipv4', '')}? Tell {arp.get('arp.src.proto_ipv4', '')}"
        if protocol == "ICMP":
            icmp = layers.get("icmp", {})
            t = icmp.get("icmp.type", "")
            return {
                "8": "Echo Request",
                "0": "Echo Reply",
                "3": "Destination Unreachable",
            }.get(t, f"Type {t}")
    except Exception:
        pass
    return ""


# ──────────────────────────────────────────────
# Background capture reader thread
# ──────────────────────────────────────────────
def _stderr_reader(proc: subprocess.Popen):
    """Reads tshark stderr and prints it to the console."""
    for line in proc.stderr:
        print(f"[tshark-error] {line}", end="", flush=True)


def _capture_reader(proc: subprocess.Popen):
    """Reads tshark JSON output line by line and puts packets in the queue."""
    global packet_queue
    pkt_count = 0
    buf = ""
    depth = 0
    in_obj = False
    for raw_line in proc.stdout:
        line = raw_line
        # tshark -T json outputs an array [ { ... }, { ... }, ... ]
        # We parse individual objects by tracking brace depth
        for ch in line:
            if ch == "{":
                if depth == 0:
                    buf = "{"
                    in_obj = True
                else:
                    buf += ch
                depth += 1
            elif ch == "}":
                depth -= 1
                if in_obj:
                    buf += ch
                if depth == 0 and in_obj:
                    pkt = parse_tshark_json(buf)
                    if pkt:
                        pkt_count += 1
                        if pkt_count % 10 == 0:
                            print(f"[debug] Received {pkt_count} packets from tshark...")
                        try:
                            packet_queue.put_nowait(pkt)
                        except queue.Full:
                            pass
                    buf = ""
                    in_obj = False
            elif in_obj:
                buf += ch


# ──────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/tshark-check")
def tshark_check():
    try:
        ts = find_tshark()
        result = subprocess.run(
            [ts, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        version_line = result.stdout.split("\n")[0]
        return jsonify({"ok": True, "version": version_line, "path": ts})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/interfaces")
def list_interfaces():
    """Return a list of {id, name} dicts.

    tshark -D outputs lines like:
        1. \\Device\\NPF_{GUID} (Ethernet)
        2. \\Device\\NPF_{GUID} (Wi-Fi)
        13. \\\\.\\USBPcap1 (USBPcap1)

    We extract:
        id   = the leading number (used as the -i argument)
        name = the friendly label inside the trailing parentheses
    """
    import re
    try:
        ts = find_tshark()
        result = subprocess.run(
            [ts, "-D"],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        if result.returncode != 0:
            stderr = result.stderr.lower()
            if "npcap" in stderr or "npf" in stderr:
                return jsonify({"error": "Npcap not found or not running. Please install Npcap.", "details": result.stderr}), 500

        ifaces = []
        # Pattern: "<num>. <device_path> (<friendly name>)"
        pattern = re.compile(r'^(\d+)\.\s+\S+.*\((.+)\)\s*$')
        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            m = pattern.match(line)
            if m:
                ifaces.append({"id": m.group(1), "name": m.group(2).strip()})
            else:
                # Fallback: try to get just the number if no parentheses
                num_match = re.match(r'^(\d+)\.\s+(\S+)', line)
                if num_match:
                    ifaces.append({"id": num_match.group(1), "name": num_match.group(2)})
        return jsonify({"interfaces": ifaces})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/capture/start", methods=["POST"])
def start_capture():
    global capture_proc
    data = request.get_json(force=True, silent=True) or {}
    # Frontend now sends the numeric interface id directly (e.g. "1", "2")
    iface = str(data.get("interface", "1")).strip()

    with capture_lock:
        if capture_proc and capture_proc.poll() is None:
            return jsonify({"error": "Capture already running"}), 409
        # Clear the queue
        while not packet_queue.empty():
            try:
                packet_queue.get_nowait()
            except queue.Empty:
                break
        try:
            ts = find_tshark()
            cmd = [ts, "-i", iface, "-T", "json", "-l", "-n"]
            create_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            capture_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                creationflags=create_flags,
            )
            # Give tshark a moment to start; if it exits immediately it's an error
            time.sleep(0.6)
            if capture_proc.poll() is not None:
                # Process exited already — grab stderr for a useful error message
                stderr_out = capture_proc.stderr.read().strip()
                capture_proc = None
                msg = stderr_out or "tshark exited immediately with no output."
                # Common hint for Windows privilege issues
                if "permission" in msg.lower() or "access" in msg.lower() or not stderr_out:
                    msg += " — Try running the app as Administrator (tshark requires elevated privileges for live capture on Windows)."
                return jsonify({"error": msg}), 500
            t_err = threading.Thread(target=_stderr_reader, args=(capture_proc,), daemon=True)
            t_err.start()
            t = threading.Thread(target=_capture_reader, args=(capture_proc,), daemon=True)
            t.start()
            return jsonify({"status": "started", "interface": iface})
        except Exception as e:
            return jsonify({"error": str(e)}), 500


@app.route("/api/capture/stop", methods=["POST"])
def stop_capture():
    global capture_proc
    with capture_lock:
        if capture_proc:
            capture_proc.terminate()
            try:
                capture_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                capture_proc.kill()
            capture_proc = None
    return jsonify({"status": "stopped"})


@app.route("/api/stream")
def stream():
    """SSE endpoint — pushes packets from the live capture queue."""
    def generate():
        yield "data: {\"connected\": true}\n\n"
        while True:
            try:
                pkt = packet_queue.get(timeout=1)
                yield f"data: {json.dumps(pkt)}\n\n"
            except queue.Empty:
                # Send a keepalive comment
                yield ": keepalive\n\n"
    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.route("/api/upload", methods=["POST"])
def upload_pcap():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400
    if not (f.filename.endswith(".pcap") or f.filename.endswith(".pcapng")):
        return jsonify({"error": "Only .pcap and .pcapng files are supported"}), 400

    save_path = UPLOAD_FOLDER / f"{uuid.uuid4().hex}_{f.filename}"
    f.save(save_path)

    try:
        ts = find_tshark()
        cmd = [ts, "-r", str(save_path), "-T", "json", "-n"]
        create_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            creationflags=create_flags,
        )
        # Only fail hard if there's no stdout at all; tshark often exits non-zero for warnings
        if not result.stdout.strip():
            return jsonify({"error": result.stderr[:500] or "tshark produced no output."}), 500

        # Parse the JSON array tshark outputs
        raw_packets = []
        try:
            raw_packets = json.loads(result.stdout)
        except json.JSONDecodeError:
            pass

        session_id = uuid.uuid4().hex
        packets = []
        session_raws = []  # parallel list of raw layers, stored server-side

        for raw_pkt in raw_packets:
            layers = raw_pkt.get("_source", {}).get("layers", {})
            frame = layers.get("frame", {})
            ip = layers.get("ip", layers.get("ipv6", {}))
            proto_raw = frame.get("frame.protocols", "")
            protocol = _highest_protocol(proto_raw)
            pkt = {
                "number": frame.get("frame.number", str(len(packets) + 1)),
                "time": frame.get("frame.time_relative", ""),
                "src": ip.get("ip.src", ip.get("ipv6.src", layers.get("eth", {}).get("eth.src", "—"))),
                "dst": ip.get("ip.dst", ip.get("ipv6.dst", layers.get("eth", {}).get("eth.dst", "—"))),
                "protocol": protocol,
                "length": frame.get("frame.len", ""),
                "info": _build_info(protocol, layers),
                # NOTE: no 'raw' here — fetched lazily via /api/packet-detail
                "sessionId": session_id,
                "idx": len(packets),
            }
            packets.append(pkt)
            session_raws.append(layers)

        # Store raw layers server-side; purge old sessions first to limit memory
        with _session_lock:
            _session_raw.clear()  # one file at a time is fine for this tool
            _session_raw[session_id] = session_raws

        return jsonify({"packets": packets, "count": len(packets), "sessionId": session_id})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "tshark timed out"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        try:
            save_path.unlink()
        except Exception:
            pass


@app.route("/api/packet-detail/<session_id>/<int:idx>")
def packet_detail(session_id: str, idx: int):
    """Return the raw tshark layers for a single packet (lazy-loaded on row click)."""
    with _session_lock:
        session = _session_raw.get(session_id)
    if session is None:
        return jsonify({"error": "Session not found"}), 404
    if idx < 0 or idx >= len(session):
        return jsonify({"error": "Index out of range"}), 404
    return jsonify({"raw": session[idx]})


if __name__ == "__main__":
    app.run(debug=True, threaded=True, host="0.0.0.0", port=5000)
