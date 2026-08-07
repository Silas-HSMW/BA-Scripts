from __future__ import annotations

import json
import subprocess
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# tshark muss installiert sein. aus apt/pacman runterziehen
TSHARK_BINARY = "tshark"
# pfad  zu pcap file manuell angeben
PCAP_PATH = Path("data_pcap/")
# pfad input/output
CONTROL_LOG_PATH = Path("data/")
OUTPUT_PATH = Path("correlated_flows.jsonl")

# Zeit toleranz in sekunden. legt fest wie weit die Client/Server zeiträume abweichen dürfen
TIME_TOLERANCE = 5

'''
zeit zu float. für einfaches rechnen mit zeiträumen
'''
def parse_iso_time(value: str) -> float:
    return datetime.fromisoformat(value).timestamp()

'''
lädt Client Log file in eine liste. eine event pro zeile erforderlich
'''
def load_jsonl(path: Path) -> list[dict]:
    records = []

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))

    return records

'''
lädt Pcap Daten aus Serverperspektive
'''
def tshark_packets(pcap_path: Path) -> list[dict]:
    # legt fest welche felder des files geladen werden
    cmd = [
        TSHARK_BINARY,
        "-r", str(pcap_path),
        "-Y", "tcp", # nur tcp
        "-T", "fields", # mit den Folgenen Feldern
        "-E", "separator=\t",
        "-E", "occurrence=f",
        "-e", "frame.time_epoch",
        "-e", "frame.len",
        "-e", "ip.src",
        "-e", "tcp.srcport",
        "-e", "ip.dst",
        "-e", "tcp.dstport",
        "-e", "tcp.stream", # lässt wireshark tcp parkete als eine zusammengehörige sitzung erkennen
        "-e", "tcp.flags.syn",
        "-e", "tcp.flags.fin",
        "-e", "tcp.flags.reset",
        "-e", "tls.handshake.type", # 1== handshake
        "-e", "tls.handshake.extensions_server_name",
        "-e", "tls.handshake.ja3",
        "-e", "tls.handshake.ja3_full",
        "-e", "tls.handshake.ja3s",
        "-e", "tls.handshake.ja3s_full",
        "-e", "tls.handshake.ja4",
        "-e", "tls.handshake.ja4_r",
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )
    # fehlerbehandlung
    if result.returncode != 0:
        if result.stdout.strip():
            print("tshark Fehlercode erhalten, stdout enthält daten, potenziell beschädigter pcap file. Prozess wird fortgesetzt....")
            print(result.stderr[-1000:])
        else:
            raise RuntimeError(
                "tshark fehler\n"
                f"STDOUT: {result.stdout[-1000:]}\n"
                f"STDERR: {result.stderr[-1000:]}"
            )

    packets = []

    for line in result.stdout.splitlines():
        parts = line.split("\t")

        while len(parts) < 12:
            parts.append("")
        # überspringt fehlende zeitstempel
        if not parts[0]:
            continue
        # überspringt fehlende ip/TCP daten
        if not parts[2] or not parts[3] or not parts[4] or not parts[5] or not parts[6]:
            continue
        # datentyp umwandlung und bennenung
        try:
            packet = {
                "time_epoch": float(parts[0]),
                "frame_len": int(parts[1]) if parts[1] else 0,
                "ip_src": parts[2],
                "tcp_srcport": int(parts[3]),
                "ip_dst": parts[4],
                "tcp_dstport": int(parts[5]),
                "tcp_stream": int(parts[6]), # Ermöglicht es später mehrere bestandteile einer Verbindung (etwa client und Server hello) einander zuzuorden
                "tcp_syn": parts[7],
                "tcp_fin": parts[8],
                "tcp_rst": parts[9],
                "tls_handshake_type": parts[10],
                "sni": parts[11],
                "ja3": parts[12],
                "ja3_full": parts[13],
                "ja3s": parts[14],
                "ja3s_full": parts[15],
                "ja4": parts[16],
                "ja4_r": parts[17],
            }

            packets.append(packet)

        except ValueError:
            continue

    return packets

'''
zusammenfassen der sitzungen/Sitzungswerte. also Paketliste zu Flowliste
'''
def aggregate_flows(packets: list[dict]) -> list[dict]:
    streams = defaultdict(list)
    # nutzt session erkennung von wireshark. jede TCP verbindung erhält eigene stream id
    for packet in packets:
        streams[packet["tcp_stream"]].append(packet)

    flows = []

    for tcp_stream, stream_packets in streams.items():
        # erhält alle Pakete eines Streams
        stream_packets = sorted(stream_packets, key=lambda x: x["time_epoch"])
        # erkennt erstes und letztes paket
        first = stream_packets[0]
        last = stream_packets[-1]

        client_ip = None
        client_port = None
        server_ip = None
        server_port = None
        # zuordnung von Server/Client Seite. Hier mit 443 möglich da nur HTTPS verkehr
        for packet in stream_packets:
            if packet["tcp_dstport"] == 443:
                client_ip = packet["ip_src"]
                client_port = packet["tcp_srcport"]
                server_ip = packet["ip_dst"]
                server_port = packet["tcp_dstport"]
                break

            if packet["tcp_srcport"] == 443:
                client_ip = packet["ip_dst"]
                client_port = packet["tcp_dstport"]
                server_ip = packet["ip_src"]
                server_port = packet["tcp_srcport"]
                break

        # Fehlerbehandlung
        if client_ip is None:
            continue

        # Counter/Varriablen festlegen
        packet_count_client_to_server = 0
        packet_count_server_to_client = 0
        bytes_client_to_server = 0
        bytes_server_to_client = 0

        sni = None

        has_client_hello = False
        has_server_hello = False

        ja3 = None
        ja3_full = None
        ja3s = None
        ja3s_full = None
        ja4 = None
        ja4_r = None

        # jedes Paket im Stream ausgewertet und zu flow werten gerechnet
        for packet in stream_packets:
            # richtung bestimmen
            is_client_to_server = (
                packet["ip_src"] == client_ip
                and packet["tcp_srcport"] == client_port
                and packet["ip_dst"] == server_ip
                and packet["tcp_dstport"] == server_port
            )

            is_server_to_client = (
                packet["ip_src"] == server_ip
                and packet["tcp_srcport"] == server_port
                and packet["ip_dst"] == client_ip
                and packet["tcp_dstport"] == client_port
            )
            # werte hinzufügen
            if is_client_to_server:
                packet_count_client_to_server += 1
                bytes_client_to_server += packet["frame_len"]

            elif is_server_to_client:
                packet_count_server_to_client += 1
                bytes_server_to_client += packet["frame_len"]
            # handshake erkennen
            if packet["tls_handshake_type"] == "1":
                has_client_hello = True

                if packet["sni"]:
                    sni = packet["sni"]
            # handshake erkennen
            if packet["tls_handshake_type"] == "2":
                has_server_hello = True

            # fingerprint werte hinzufügen
            if packet["ja3"]:
                ja3 = packet["ja3"]

            if packet["ja3_full"]:
                ja3_full = packet["ja3_full"]

            if packet["ja3s"]:
                ja3s = packet["ja3s"]

            if packet["ja3s_full"]:
                ja3s_full = packet["ja3s_full"]

            if packet["ja4"]:
                ja4 = packet["ja4"]

            if packet["ja4_r"]:
                ja4_r = packet["ja4_r"]

                # abgeleitete Flow-Features berechnen
            packet_count_total = len(stream_packets)
            bytes_total = bytes_client_to_server + bytes_server_to_client

            mean_packet_size = bytes_total / packet_count_total if packet_count_total else 0

            mean_packet_size_client_to_server = (
                bytes_client_to_server / packet_count_client_to_server
                if packet_count_client_to_server
                else 0
            )

            mean_packet_size_server_to_client = (
                bytes_server_to_client / packet_count_server_to_client
                if packet_count_server_to_client
                else 0
            )

            bytes_ratio_client_to_server = (
                bytes_client_to_server / bytes_total
                if bytes_total
                else 0
            )

            packets_ratio_client_to_server = (
                packet_count_client_to_server / packet_count_total
                if packet_count_total
                else 0
            )
        # zusammenfügen der bestimmten flow werte
        flows.append({
            "tcp_stream": tcp_stream,
            "flow_start_epoch": first["time_epoch"],
            "flow_end_epoch": last["time_epoch"],
            "flow_duration": last["time_epoch"] - first["time_epoch"],

            "local_ip": client_ip,
            "local_port": client_port,
            "remote_ip": server_ip,
            "remote_port": server_port,

            "packet_count_total": packet_count_total,
            "packet_count_client_to_server": packet_count_client_to_server,
            "packet_count_server_to_client": packet_count_server_to_client,

            "bytes_total": bytes_total,
            "bytes_client_to_server": bytes_client_to_server,
            "bytes_server_to_client": bytes_server_to_client,

            "mean_packet_size": mean_packet_size,
            "mean_packet_size_client_to_server": mean_packet_size_client_to_server,
            "mean_packet_size_server_to_client": mean_packet_size_server_to_client,
            "bytes_ratio_client_to_server": bytes_ratio_client_to_server,
            "packets_ratio_client_to_server": packets_ratio_client_to_server,


            "has_client_hello": has_client_hello,
            "has_server_hello": has_server_hello,
            "sni": sni,

            "ja3": ja3,
            "ja3_full": ja3_full,
            "ja3s": ja3s,
            "ja3s_full": ja3s_full,
            "ja4": ja4,
            "ja4_r": ja4_r,

        })

    return flows

'''
überprüft ob ein zeitfensterinnerhalb eines varriablen Toleranzbereiches liegt
'''
def event_time_window(event: dict, tolerance_seconds: int | None = None) -> tuple[float | None, float | None]:
    start = event.get("start_time")
    end = event.get("end_time")

    if tolerance_seconds is None:
        tolerance_seconds = TIME_TOLERANCE

    if not start or not end:
        return None, None

    return (
        parse_iso_time(start) - tolerance_seconds,
        parse_iso_time(end) + tolerance_seconds,
    )

'''
bestimmt ob ein Flow Event und ein Log event zusammengehören
'''
def flow_matches_event(flow: dict, event: dict) -> bool:
    # wenn fehlercode in logs = false
    if event.get("status") not in {"ok", "ambiguous_flows"}:
        return False
    # wenn ziel ip nicht gleich = false
    if event.get("target_ip") != flow["remote_ip"]:
        return False
    # wenn dst port nicht gleich
    if int(event.get("target_port", 0)) != flow["remote_port"]:
        return False
    # scr port zufällig, zusammen mit reduzierter anfragerate sehr unwahrscheinlich das 2 verbindungen vom gleichen port ausgehen. zeit daher auf höhe toleranz 180 (3min) um mismatches in großen datensätzen auszuschliesen
    if event.get("local_ip") and event.get("local_port"):
        start, end = event_time_window(event, 180)

        if start is None or end is None:
            return False

        return (
                event["local_ip"] == flow["local_ip"]
                and int(event["local_port"]) == flow["local_port"]
                and start <= flow["flow_start_epoch"] <= end
        )

    # andernfalls wird die eventtime genutzt um sie zeitlich zu korrelieren
    start, end = event_time_window(event)
    # fehler bei ungünltigem zeitfenster
    if start is None or end is None:
        return False
    # Liegt der Startzeitpunkt des Flows im Event-Zeitfenster -> true/false
    return start <= flow["flow_start_epoch"] <= end


def correlate(events: list[dict], flows: list[dict]) -> tuple[list[dict], dict]:
    # summe für ergebnisszeile
    correlated = []
    # set an event ids. wenn meherere Flows im gleichen event nutzen werden sie nicht mehrfach gezählt
    used_event_ids = set()
    unused_events = []
    # für jedes Event aus den logs
    for event in events:
        matches = []
        # jeder flow auf ein ach prüfen
        for flow in flows:
            if flow_matches_event(flow, event):
                matches.append(flow)

        if matches:
            used_event_ids.add(event.get("event_id"))
        else:
            unused_events.append(event)
        # eventdaten zu flowdaten hinzufügen
        for flow in matches:
            row = {
                "event_id": event.get("event_id"),
                "run_id": event.get("run_id"),
                "client_id": event.get("client_id"),
                "application": event.get("application"),
                "application_version": event.get("application_version"),

                "server_name": event.get("server_name"),
                "target_host": event.get("target_host"),
                "target_ip": event.get("target_ip"),
                "target_port": event.get("target_port"),
                "selected_endpoint": event.get("selected_endpoint"),
                "event_status": event.get("status"),

                "correlation_match_count": len(matches),
            }

            row.update(flow)
            correlated.append(row)
    # status für output zusammenfassen
    stats = {
        "client_log_rows_total": len(events),
        "client_log_rows_used": len(used_event_ids),
        "client_log_rows_unused": len(unused_events),
        "correlated_flow_rows": len(correlated),
    }

    return correlated, stats


def write_jsonl(path: Path, records: list[dict]) -> None:
    with path.open("a", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

def main():
    # Files überprüfen
    if not PCAP_PATH.exists():
        raise RuntimeError(f"PCAP nicht Gefunden: {PCAP_PATH}")

    if not CONTROL_LOG_PATH.exists():
        raise RuntimeError(f"Client Logs nicht gefunden: {CONTROL_LOG_PATH}")
    # daten laden
    events = load_jsonl(CONTROL_LOG_PATH)
    packets = tshark_packets(PCAP_PATH)
    # flows zusammenfassen
    flows = aggregate_flows(packets)
    # Korrelation der flow daten zu Client event log daten
    correlated, correlation_stats = correlate(events, flows)
    # output schreiben
    write_jsonl(OUTPUT_PATH, correlated)

    print(f"Client-Log-Zeilen insgesamt: {len(events)}")
    print(f"Client-Log-Zeilen mit mindestens einem PCAP-Flow: {correlation_stats['client_log_rows_used']}")
    print(f"Client-Log-Zeilen ohne passenden PCAP-Flow: {correlation_stats['client_log_rows_unused']}")
    print(f"Aus der PCAP gelesene TCP-Pakete: {len(packets)}")
    print(f"Aus der PCAP gebildete TCP-Flows: {len(flows)}")
    print(f"Korrelierte Ergebniszeilen Event-Flow-Zuordnungen: {len(correlated)}")
    print(f"Ausgabedatei: {OUTPUT_PATH}")

# Hintergedanke: mehrere Control-Logs werden mit den beiden Server-PCAPs kombiniert. Damit es nicht manuell festgelegt werden muss wird jeder PCAP file mit jedem Control file abgeglichen
if __name__ == "__main__":
    pcap_dir = PCAP_PATH
    log_dir = CONTROL_LOG_PATH
    output_dir = OUTPUT_PATH

    if not pcap_dir.exists() or not pcap_dir.is_dir():
        raise RuntimeError(f"PCAP-Ordner nicht gefunden: {pcap_dir}")

    if not log_dir.exists() or not log_dir.is_dir():
        raise RuntimeError(f"Client-Log-Ordner nicht gefunden: {log_dir}")

    pcap_files = sorted(
        list(pcap_dir.glob("*.pcap")) +
        list(pcap_dir.glob("*.pcapng"))
    )

    log_files = sorted(
        list(log_dir.glob("*.jsonl")) +
        list(log_dir.glob("*.log"))
    )

    if not pcap_files:
        raise RuntimeError(f"Keine PCAP-Dateien gefunden in: {pcap_dir}")

    if not log_files:
        raise RuntimeError(f"Keine Log-Dateien gefunden in: {log_dir}")

    output_dir.mkdir(parents=True, exist_ok=True)

    for log_path in log_files:
        for pcap_path in pcap_files:
            PCAP_PATH = pcap_path
            CONTROL_LOG_PATH = log_path
            OUTPUT_PATH = output_dir / f"{log_path.stem}__{pcap_path.stem}.jsonl"

            main()from __future__ import annotations

import json
import subprocess
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# tshark muss installiert sein. aus apt/pacman runterziehen
TSHARK_BINARY = "tshark"
# pfad  zu pcap file manuell angeben
# server_capture2.pcap
# 2026-07-10_10-00-41
# 2026-07-10_10-01-55
PCAP_PATH = Path("data_pcap/")
# pfad input/output
######################### Es gib mehr client als controll events. schau dier das später an!!!
CONTROL_LOG_PATH = Path("data/")
OUTPUT_PATH = Path("correlated_flows.jsonl")

# Zeit toleranz in sekunden. legt fest wie weit die Client/Server zeiträume abweichen dürfen
TIME_TOLERANCE = 5

'''
zeit zu float. für einfaches rechnen mit zeiträumen
'''
def parse_iso_time(value: str) -> float:
    return datetime.fromisoformat(value).timestamp()

'''
lädt Client Log file in eine liste. eine event pro zeile erforderlich
'''
def load_jsonl(path: Path) -> list[dict]:
    records = []

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))

    return records

'''
lädt Pcap Daten aus Serverperspektive
'''
def tshark_packets(pcap_path: Path) -> list[dict]:
    # legt fest welche felder des files geladen werden
    cmd = [
        TSHARK_BINARY,
        "-r", str(pcap_path),
        "-Y", "tcp", # nur tcp
        "-T", "fields", # mit den Folgenen Feldern
        "-E", "separator=\t",
        "-E", "occurrence=f",
        "-e", "frame.time_epoch",
        "-e", "frame.len",
        "-e", "ip.src",
        "-e", "tcp.srcport",
        "-e", "ip.dst",
        "-e", "tcp.dstport",
        "-e", "tcp.stream", # lässt wireshark tcp parkete als eine zusammengehörige sitzung erkennen
        "-e", "tcp.flags.syn",
        "-e", "tcp.flags.fin",
        "-e", "tcp.flags.reset",
        "-e", "tls.handshake.type", # 1== handshake
        "-e", "tls.handshake.extensions_server_name",
        "-e", "tls.handshake.ja3",
        "-e", "tls.handshake.ja3_full",
        "-e", "tls.handshake.ja3s",
        "-e", "tls.handshake.ja3s_full",
        "-e", "tls.handshake.ja4",
        "-e", "tls.handshake.ja4_r",
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )
    # fehlerbehandlung
    if result.returncode != 0:
        if result.stdout.strip():
            print("tshark Fehlercode erhalten, stdout enthält daten, potenziell beschädigter pcap file. Prozess wird fortgesetzt....")
            print(result.stderr[-1000:])
        else:
            raise RuntimeError(
                "tshark fehler\n"
                f"STDOUT: {result.stdout[-1000:]}\n"
                f"STDERR: {result.stderr[-1000:]}"
            )

    packets = []

    for line in result.stdout.splitlines():
        parts = line.split("\t")

        while len(parts) < 12:
            parts.append("")
        # überspringt fehlende zeitstempel
        if not parts[0]:
            continue
        # überspringt fehlende ip/TCP daten
        if not parts[2] or not parts[3] or not parts[4] or not parts[5] or not parts[6]:
            continue
        # datentyp umwandlung und bennenung
        try:
            packet = {
                "time_epoch": float(parts[0]),
                "frame_len": int(parts[1]) if parts[1] else 0,
                "ip_src": parts[2],
                "tcp_srcport": int(parts[3]),
                "ip_dst": parts[4],
                "tcp_dstport": int(parts[5]),
                "tcp_stream": int(parts[6]), # Ermöglicht es später mehrere bestandteile einer Verbindung (etwa client und Server hello) einander zuzuorden
                "tcp_syn": parts[7],
                "tcp_fin": parts[8],
                "tcp_rst": parts[9],
                "tls_handshake_type": parts[10],
                "sni": parts[11],
                "ja3": parts[12],
                "ja3_full": parts[13],
                "ja3s": parts[14],
                "ja3s_full": parts[15],
                "ja4": parts[16],
                "ja4_r": parts[17],
            }

            packets.append(packet)

        except ValueError:
            continue

    return packets

'''
zusammenfassen der sitzungen/Sitzungswerte. also Paketliste zu Flowliste
'''
def aggregate_flows(packets: list[dict]) -> list[dict]:
    streams = defaultdict(list)
    # nutzt session erkennung von wireshark. jede TCP verbindung erhält eigene stream id
    for packet in packets:
        streams[packet["tcp_stream"]].append(packet)

    flows = []

    for tcp_stream, stream_packets in streams.items():
        # erhält alle Pakete eines Streams
        stream_packets = sorted(stream_packets, key=lambda x: x["time_epoch"])
        # erkennt erstes und letztes paket
        first = stream_packets[0]
        last = stream_packets[-1]

        client_ip = None
        client_port = None
        server_ip = None
        server_port = None
        # zuordnung von Server/Client Seite. Hier mit 443 möglich da nur HTTPS verkehr
        for packet in stream_packets:
            if packet["tcp_dstport"] == 443:
                client_ip = packet["ip_src"]
                client_port = packet["tcp_srcport"]
                server_ip = packet["ip_dst"]
                server_port = packet["tcp_dstport"]
                break

            if packet["tcp_srcport"] == 443:
                client_ip = packet["ip_dst"]
                client_port = packet["tcp_dstport"]
                server_ip = packet["ip_src"]
                server_port = packet["tcp_srcport"]
                break

        # Fehlerbehandlung
        if client_ip is None:
            continue

        # Counter/Varriablen festlegen
        packet_count_client_to_server = 0
        packet_count_server_to_client = 0
        bytes_client_to_server = 0
        bytes_server_to_client = 0

        sni = None

        has_client_hello = False
        has_server_hello = False

        ja3 = None
        ja3_full = None
        ja3s = None
        ja3s_full = None
        ja4 = None
        ja4_r = None

        # jedes Paket im Stream ausgewertet und zu flow werten gerechnet
        for packet in stream_packets:
            # richtung bestimmen
            is_client_to_server = (
                packet["ip_src"] == client_ip
                and packet["tcp_srcport"] == client_port
                and packet["ip_dst"] == server_ip
                and packet["tcp_dstport"] == server_port
            )

            is_server_to_client = (
                packet["ip_src"] == server_ip
                and packet["tcp_srcport"] == server_port
                and packet["ip_dst"] == client_ip
                and packet["tcp_dstport"] == client_port
            )
            # werte hinzufügen
            if is_client_to_server:
                packet_count_client_to_server += 1
                bytes_client_to_server += packet["frame_len"]

            elif is_server_to_client:
                packet_count_server_to_client += 1
                bytes_server_to_client += packet["frame_len"]
            # handshake erkennen
            if packet["tls_handshake_type"] == "1":
                has_client_hello = True

                if packet["sni"]:
                    sni = packet["sni"]
            # handshake erkennen
            if packet["tls_handshake_type"] == "2":
                has_server_hello = True

            # fingerprint werte hinzufügen
            if packet["ja3"]:
                ja3 = packet["ja3"]

            if packet["ja3_full"]:
                ja3_full = packet["ja3_full"]

            if packet["ja3s"]:
                ja3s = packet["ja3s"]

            if packet["ja3s_full"]:
                ja3s_full = packet["ja3s_full"]

            if packet["ja4"]:
                ja4 = packet["ja4"]

            if packet["ja4_r"]:
                ja4_r = packet["ja4_r"]

                # abgeleitete Flow-Features berechnen
            packet_count_total = len(stream_packets)
            bytes_total = bytes_client_to_server + bytes_server_to_client

            mean_packet_size = bytes_total / packet_count_total if packet_count_total else 0

            mean_packet_size_client_to_server = (
                bytes_client_to_server / packet_count_client_to_server
                if packet_count_client_to_server
                else 0
            )

            mean_packet_size_server_to_client = (
                bytes_server_to_client / packet_count_server_to_client
                if packet_count_server_to_client
                else 0
            )

            bytes_ratio_client_to_server = (
                bytes_client_to_server / bytes_total
                if bytes_total
                else 0
            )

            packets_ratio_client_to_server = (
                packet_count_client_to_server / packet_count_total
                if packet_count_total
                else 0
            )
        # zusammenfügen der bestimmten flow werte
        flows.append({
            "tcp_stream": tcp_stream,
            "flow_start_epoch": first["time_epoch"],
            "flow_end_epoch": last["time_epoch"],
            "flow_duration": last["time_epoch"] - first["time_epoch"],

            "local_ip": client_ip,
            "local_port": client_port,
            "remote_ip": server_ip,
            "remote_port": server_port,

            "packet_count_total": packet_count_total,
            "packet_count_client_to_server": packet_count_client_to_server,
            "packet_count_server_to_client": packet_count_server_to_client,

            "bytes_total": bytes_total,
            "bytes_client_to_server": bytes_client_to_server,
            "bytes_server_to_client": bytes_server_to_client,

            "mean_packet_size": mean_packet_size,
            "mean_packet_size_client_to_server": mean_packet_size_client_to_server,
            "mean_packet_size_server_to_client": mean_packet_size_server_to_client,
            "bytes_ratio_client_to_server": bytes_ratio_client_to_server,
            "packets_ratio_client_to_server": packets_ratio_client_to_server,


            "has_client_hello": has_client_hello,
            "has_server_hello": has_server_hello,
            "sni": sni,

            "ja3": ja3,
            "ja3_full": ja3_full,
            "ja3s": ja3s,
            "ja3s_full": ja3s_full,
            "ja4": ja4,
            "ja4_r": ja4_r,

        })

    return flows

'''
überprüft ob ein zeitfensterinnerhalb eines varriablen Toleranzbereiches liegt
'''
def event_time_window(event: dict, tolerance_seconds: int | None = None) -> tuple[float | None, float | None]:
    start = event.get("start_time")
    end = event.get("end_time")

    if tolerance_seconds is None:
        tolerance_seconds = TIME_TOLERANCE

    if not start or not end:
        return None, None

    return (
        parse_iso_time(start) - tolerance_seconds,
        parse_iso_time(end) + tolerance_seconds,
    )

'''
bestimmt ob ein Flow Event und ein Log event zusammengehören
'''
def flow_matches_event(flow: dict, event: dict) -> bool:
    # wenn fehlercode in logs = false
    if event.get("status") not in {"ok", "ambiguous_flows"}:
        return False
    # wenn ziel ip nicht gleich = false
    if event.get("target_ip") != flow["remote_ip"]:
        return False
    # wenn dst port nicht gleich
    if int(event.get("target_port", 0)) != flow["remote_port"]:
        return False
    # scr port zufällig, zusammen mit reduzierte2026-07-10_10-00-41r anfragerate sehr unwahrscheinlich das 2 verbindungen vom gleichen port ausgehen. zeit daher auf höhe toleranz 180 (3min) um mismatches in großen datensätzen auszuschliesen
    if event.get("local_ip") and event.get("local_port"):
        start, end = event_time_window(event, 180)

        if start is None or end is None:
            return False

        return (
                event["local_ip"] == flow["local_ip"]
                and int(event["local_port"]) == flow["local_port"]
                and start <= flow["flow_start_epoch"] <= end
        )

    # andernfalls wird die eventtime genutzt um sie zeitlich zu korrelieren
    start, end = event_time_window(event)
    # fehler bei ungünltigem zeitfenster
    if start is None or end is None:
        return False
    # Liegt der Startzeitpunkt des Flows im Event-Zeitfenster -> true/false
    return start <= flow["flow_start_epoch"] <= end


def correlate(events: list[dict], flows: list[dict]) -> tuple[list[dict], dict]:
    # summe für ergebnisszeile
    correlated = []
    # set an event ids. wenn meherere Flows im gleichen event nutzen werden sie nicht mehrfach gezählt
    used_event_ids = set()
    unused_events = []
    # für jedes Event aus den logs
    for event in events:
        matches = []
        # jeder flow auf ein ach prüfen
        for flow in flows:
            if flow_matches_event(flow, event):
                matches.append(flow)

        if matches:
            used_event_ids.add(event.get("event_id"))
        else:
            unused_events.append(event)
        # eventdaten zu flowdaten hinzufügen
        for flow in matches:
            row = {
                "event_id": event.get("event_id"),
                "run_id": event.get("run_id"),
                "client_id": event.get("client_id"),
                "application": event.get("application"),
                "application_version": event.get("application_version"),

                "server_name": event.get("server_name"),
                "target_host": event.get("target_host"),
                "target_ip": event.get("target_ip"),
                "target_port": event.get("target_port"),
                "selected_endpoint": event.get("selected_endpoint"),
                "event_status": event.get("status"),

                "correlation_match_count": len(matches),
            }

            row.update(flow)
            correlated.append(row)
    # status für output zusammenfassen
    stats = {
        "client_log_rows_total": len(events),
        "client_log_rows_used": len(used_event_ids),
        "client_log_rows_unused": len(unused_events),
        "correlated_flow_rows": len(correlated),
    }

    return correlated, stats


def write_jsonl(path: Path, records: list[dict]) -> None:
    with path.open("a", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

def main():
    # Files überprüfen
    if not PCAP_PATH.exists():
        raise RuntimeError(f"PCAP nicht Gefunden: {PCAP_PATH}")

    if not CONTROL_LOG_PATH.exists():
        raise RuntimeError(f"Client Logs nicht gefunden: {CONTROL_LOG_PATH}")
    # daten laden
    events = load_jsonl(CONTROL_LOG_PATH)
    packets = tshark_packets(PCAP_PATH)
    # flows zusammenfassen
    flows = aggregate_flows(packets)
    # Korrelation der flow daten zu Client event log daten
    correlated, correlation_stats = correlate(events, flows)
    # output schreiben
    write_jsonl(OUTPUT_PATH, correlated)

    print(f"Client-Log-Zeilen insgesamt: {len(events)}")
    print(f"Client-Log-Zeilen mit mindestens einem PCAP-Flow: {correlation_stats['client_log_rows_used']}")
    print(f"Client-Log-Zeilen ohne passenden PCAP-Flow: {correlation_stats['client_log_rows_unused']}")
    print(f"Aus der PCAP gelesene TCP-Pakete: {len(packets)}")
    print(f"Aus der PCAP gebildete TCP-Flows: {len(flows)}")
    print(f"Korrelierte Ergebniszeilen Event-Flow-Zuordnungen: {len(correlated)}")
    print(f"Ausgabedatei: {OUTPUT_PATH}")


if __name__ == "__main__":
    pcap_dir = PCAP_PATH
    log_dir = CONTROL_LOG_PATH
    output_dir = OUTPUT_PATH

    if not pcap_dir.exists() or not pcap_dir.is_dir():
        raise RuntimeError(f"PCAP-Ordner nicht gefunden: {pcap_dir}")

    if not log_dir.exists() or not log_dir.is_dir():
        raise RuntimeError(f"Client-Log-Ordner nicht gefunden: {log_dir}")

    pcap_files = sorted(
        list(pcap_dir.glob("*.pcap")) +
        list(pcap_dir.glob("*.pcapng"))
    )

    log_files = sorted(
        list(log_dir.glob("*.jsonl")) +
        list(log_dir.glob("*.log"))
    )

    if not pcap_files:
        raise RuntimeError(f"Keine PCAP-Dateien gefunden in: {pcap_dir}")

    if not log_files:
        raise RuntimeError(f"Keine Log-Dateien gefunden in: {log_dir}")

    output_dir.mkdir(parents=True, exist_ok=True)

    for log_path in log_files:
        for pcap_path in pcap_files:
            PCAP_PATH = pcap_path
            CONTROL_LOG_PATH = log_path
            OUTPUT_PATH = output_dir / f"{log_path.stem}__{pcap_path.stem}.jsonl"

            main()
