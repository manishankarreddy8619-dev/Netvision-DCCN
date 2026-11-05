"""
NetVision TCP Sender Client
Connects to a remote NetVision Receiver, sends text messages, transfers binary files,
measures real-time transfer speed, and verifies end-to-end SHA-256 integrity.
"""

import os
import socket
import time
import logging
from typing import Dict, Any, Optional, Callable
from pathlib import Path

from network.file_transfer import (
    FrameType,
    send_frame,
    recv_frame,
    send_json,
    recv_json,
    compute_file_sha256,
    format_bytes,
    format_speed,
    DEFAULT_BUFFER_SIZE,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [Sender] %(message)s")
logger = logging.getLogger("NetVision.Sender")


class SenderClient:
    def __init__(self, target_host: str, target_port: int = 65432, timeout: float = 15.0):
        self.target_host = target_host
        self.target_port = target_port
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None

    def connect(self) -> bool:
        """Establish TCP connection to receiver."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.target_host, self.target_port))
            logger.info(f"Connected to receiver at {self.target_host}:{self.target_port}")
            return True
        except ConnectionRefusedError:
            logger.error(f"Connection refused at {self.target_host}:{self.target_port}. Is the receiver running?")
            self.close()
            raise ConnectionRefusedError(f"Cannot connect to {self.target_host}:{self.target_port}. Receiver is not active or blocked by firewall.")
        except socket.timeout:
            logger.error(f"Connection timed out to {self.target_host}:{self.target_port}")
            self.close()
            raise TimeoutError(f"Connection timed out trying to reach {self.target_host}:{self.target_port}.")
        except Exception as e:
            logger.error(f"Failed to connect to {self.target_host}:{self.target_port}: {e}")
            self.close()
            raise

    def close(self) -> None:
        """Close socket connection safely."""
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def test_connection(self) -> Dict[str, Any]:
        """Ping receiver and measure round-trip time (RTT)."""
        was_connected = self.sock is not None
        if not was_connected:
            self.connect()

        t_start = time.perf_counter()
        send_frame(self.sock, FrameType.PING)
        frame_type, resp = recv_json(self.sock, expected_type=FrameType.PONG)
        rtt_ms = (time.perf_counter() - t_start) * 1000.0

        if not was_connected:
            self.close()

        return {
            "status": "connected",
            "target": f"{self.target_host}:{self.target_port}",
            "rtt_ms": round(rtt_ms, 2)
        }

    def send_message(self, message: str) -> Dict[str, Any]:
        """Send a UTF-8 text message and wait for receiver acknowledgement."""
        should_close = False
        if not self.sock:
            self.connect()
            should_close = True

        msg_bytes = message.encode("utf-8")
        start_time = time.time()

        try:
            send_frame(self.sock, FrameType.MSG, msg_bytes)
            frame_type, ack = recv_json(self.sock, expected_type=FrameType.ACK)
            duration = max(time.time() - start_time, 0.0001)

            result = {
                "status": "success",
                "type": "message",
                "bytes_sent": len(msg_bytes),
                "duration_seconds": round(duration, 4),
                "ack": ack,
                "timestamp": time.time(),
                "target": f"{self.target_host}:{self.target_port}"
            }
            logger.info(f"Message sent to {self.target_host}:{self.target_port} in {duration:.4f}s")
            return result
        finally:
            if should_close:
                self.close()

    def send_file(
        self,
        filepath: str,
        progress_callback: Optional[Callable[[int, int, float], None]] = None
    ) -> Dict[str, Any]:
        """
        Send a local file to the receiver with SHA-256 verification and speed calculation.

        Args:
            filepath: Path to the local file to upload.
            progress_callback: Optional callback(transferred_bytes, total_bytes, current_speed_str)
        """
        path = Path(filepath).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {filepath}")

        file_size = path.stat().st_size
        filename = path.name

        logger.info(f"Computing SHA-256 hash for '{filename}' ({format_bytes(file_size)})...")
        local_sha256 = compute_file_sha256(str(path)).lower()
        logger.info(f"Local SHA-256: {local_sha256}")

        should_close = False
        if not self.sock:
            self.connect()
            should_close = True

        start_time = time.time()
        bytes_sent = 0

        try:
            # 1. Send metadata
            meta = {
                "filename": filename,
                "size": file_size,
                "sha256": local_sha256
            }
            send_json(self.sock, FrameType.FILE_META, meta)

            # 2. Wait for receiver to acknowledge ready
            f_type, ready_ack = recv_json(self.sock)
            if f_type == FrameType.ERROR:
                raise RuntimeError(f"Receiver rejected transfer: {ready_ack.get('reason', 'Unknown error')}")
            if ready_ack.get("status") != "ready_for_chunks":
                raise RuntimeError(f"Unexpected receiver status: {ready_ack}")

            # 3. Stream file chunks
            with open(path, "rb") as f:
                while chunk := f.read(DEFAULT_BUFFER_SIZE):
                    send_frame(self.sock, FrameType.FILE_CHUNK, chunk)
                    bytes_sent += len(chunk)
                    elapsed = max(time.time() - start_time, 0.0001)
                    if progress_callback:
                        progress_callback(bytes_sent, file_size, bytes_sent / elapsed)

            # 4. Signal transfer completion
            send_frame(self.sock, FrameType.FILE_END)

            # 5. Receive final validation ACK from receiver
            f_type, final_ack = recv_json(self.sock)
            duration = max(time.time() - start_time, 0.0001)
            speed_str = format_speed(bytes_sent, duration)

            if f_type == FrameType.ERROR:
                raise RuntimeError(f"Receiver error: {final_ack.get('reason')}")

            integrity_verified = final_ack.get("integrity_verified", False)
            remote_sha256 = final_ack.get("actual_sha256", "").lower()

            result = {
                "status": "completed" if integrity_verified else "corrupted",
                "filename": filename,
                "file_size": file_size,
                "file_size_formatted": format_bytes(file_size),
                "bytes_transferred": bytes_sent,
                "duration_seconds": round(duration, 3),
                "speed": speed_str,
                "sender_ip": socket.gethostbyname(socket.gethostname()),
                "receiver_ip": self.target_host,
                "receiver_port": self.target_port,
                "local_sha256": local_sha256,
                "remote_sha256": remote_sha256,
                "integrity_verified": integrity_verified,
                "timestamp": time.time()
            }

            logger.info(f"File transfer finished. Duration: {duration:.2f}s, Speed: {speed_str}, Integrity: {integrity_verified}")
            return result
        finally:
            if should_close:
                self.close()


def run_standalone_sender(
    host: str,
    port: int = 65432,
    message: Optional[str] = None,
    file_path: Optional[str] = None
):
    """Entrypoint for running the sender directly from the terminal."""
    client = SenderClient(target_host=host, target_port=port)
    print("=" * 65)
    print(f"🚀 NetVision TCP Sender Client connecting to {host}:{port}")
    print("=" * 65)

    try:
        ping_res = client.test_connection()
        print(f"✅ Connection successful! RTT: {ping_res['rtt_ms']} ms")

        if message:
            print(f"📤 Sending text message: '{message}'")
            res = client.send_message(message)
            print(f"✅ Ack: {res['ack']['message']} (Duration: {res['duration_seconds']}s)")

        if file_path:
            print(f"📁 Sending file: {file_path}")
            res = client.send_file(
                file_path,
                progress_callback=lambda cur, tot, spd: print(f"  Progress: {cur}/{tot} bytes ({format_speed(cur, cur/max(spd, 0.001))})", end="\r")
            )
            print()
            print("=" * 65)
            print(f"✅ Transfer Completed: {res['filename']}")
            print(f"📊 Size: {res['file_size_formatted']} | Duration: {res['duration_seconds']}s | Speed: {res['speed']}")
            print(f"🔒 SHA-256 Integrity Verified: {res['integrity_verified']}")
            print(f"🔑 Local Hash : {res['local_sha256']}")
            print(f"🔑 Remote Hash: {res['remote_sha256']}")
            print("=" * 65)

    except Exception as e:
        print(f"❌ Transfer failed: {e}")
    finally:
        client.close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="NetVision TCP Sender Client")
    parser.add_argument("--host", required=True, help="Target receiver IP address")
    parser.add_argument("--port", type=int, default=65432, help="Target receiver port (default: 65432)")
    parser.add_argument("--msg", default=None, help="Text message to send")
    parser.add_argument("--file", default=None, help="Path of file to send")
    args = parser.parse_args()

    run_standalone_sender(host=args.host, port=args.port, message=args.msg, file_path=args.file)
