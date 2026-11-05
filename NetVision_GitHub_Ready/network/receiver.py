"""
NetVision TCP Receiver Server
Listens for authorized inbound connections from Laptop A (or other nodes),
receives text messages and binary files with framing, verifies SHA-256 integrity,
and prevents directory traversal.
"""

import os
import socket
import threading
import time
import logging
from typing import Optional, Callable, Dict, Any, List
from pathlib import Path

from network.file_transfer import (
    FrameType,
    recv_frame,
    send_json,
    recv_json,
    sanitize_filename,
    compute_file_sha256,
    format_bytes,
    format_speed,
    MAX_ALLOWED_FILE_SIZE,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [Receiver] %(message)s")
logger = logging.getLogger("NetVision.Receiver")


class ReceiverServer:
    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 65432,
        save_dir: Optional[str] = None,
        on_event: Optional[Callable[[Dict[str, Any]], None]] = None,
        max_file_size: int = MAX_ALLOWED_FILE_SIZE,
    ):
        self.host = host
        self.port = port
        self.save_dir = Path(save_dir or os.path.join(os.path.dirname(__file__), "..", "data", "received_files")).resolve()
        self.save_dir.mkdir(parents=True, exist_ok=True)
        self.on_event = on_event
        self.max_file_size = max_file_size

        self.server_sock: Optional[socket.socket] = None
        self._is_running = False
        self._thread: Optional[threading.Thread] = None
        self.transfer_history: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def start(self) -> None:
        """Start receiver in a background thread."""
        if self._is_running:
            logger.warning("Receiver server is already running.")
            return

        self._is_running = True
        self._thread = threading.Thread(target=self._run_server, daemon=True, name="ReceiverServerThread")
        self._thread.start()
        logger.info(f"Receiver server started on {self.host}:{self.port}, storing files to {self.save_dir}")

    def stop(self) -> None:
        """Gracefully shut down the receiver server socket."""
        self._is_running = False
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        logger.info("Receiver server stopped.")

    @property
    def is_running(self) -> bool:
        return self._is_running

    def _emit_event(self, event_type: str, data: Dict[str, Any]) -> None:
        event = {"timestamp": time.time(), "type": event_type, **data}
        with self._lock:
            self.transfer_history.append(event)
        if self.on_event:
            try:
                self.on_event(event)
            except Exception as e:
                logger.error(f"Error in on_event callback: {e}")

    def _run_server(self) -> None:
        try:
            self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_sock.bind((self.host, self.port))
            self.server_sock.listen(5)
            self.server_sock.settimeout(1.0)
        except Exception as e:
            logger.error(f"Failed to bind receiver socket to {self.host}:{self.port}: {e}")
            self._is_running = False
            return

        while self._is_running:
            try:
                client_sock, client_addr = self.server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            client_thread = threading.Thread(
                target=self._handle_client,
                args=(client_sock, client_addr),
                daemon=True,
                name=f"ClientHandler-{client_addr[0]}:{client_addr[1]}"
            )
            client_thread.start()

    def _handle_client(self, client_sock: socket.socket, client_addr: tuple) -> None:
        client_ip, client_port = client_addr
        logger.info(f"Connection accepted from {client_ip}:{client_port}")
        self._emit_event("client_connected", {"client_ip": client_ip, "client_port": client_port})

        client_sock.settimeout(30.0)

        try:
            while self._is_running:
                try:
                    frame_type, payload = recv_frame(client_sock)
                except (ConnectionResetError, EOFError):
                    logger.info(f"Client {client_ip}:{client_port} disconnected.")
                    break
                except socket.timeout:
                    logger.warning(f"Client {client_ip}:{client_port} socket timed out.")
                    break

                if frame_type == FrameType.MSG:
                    message_text = payload.decode("utf-8", errors="replace")
                    logger.info(f"Message from {client_ip}: {message_text}")
                    self._emit_event("message_received", {
                        "client_ip": client_ip,
                        "client_port": client_port,
                        "message": message_text,
                        "size_bytes": len(payload)
                    })
                    send_json(client_sock, FrameType.ACK, {
                        "status": "success",
                        "type": "message",
                        "message": "Message received successfully."
                    })

                elif frame_type == FrameType.FILE_META:
                    self._handle_file_transfer(client_sock, client_addr, payload)

                elif frame_type == FrameType.PING:
                    send_json(client_sock, FrameType.PONG, {"status": "alive"})

                else:
                    logger.warning(f"Unexpected frame type received: {frame_type}")

        except Exception as e:
            logger.error(f"Error handling client {client_ip}:{client_port} - {e}")
        finally:
            try:
                client_sock.close()
            except Exception:
                pass
            self._emit_event("client_disconnected", {"client_ip": client_ip, "client_port": client_port})

    def _handle_file_transfer(self, client_sock: socket.socket, client_addr: tuple, meta_payload: bytes) -> None:
        import json
        client_ip, client_port = client_addr
        meta = json.loads(meta_payload.decode("utf-8"))
        raw_filename = meta.get("filename", "unknown.bin")
        expected_size = meta.get("size", 0)
        expected_sha256 = meta.get("sha256", "").lower()

        if expected_size > self.max_file_size:
            send_json(client_sock, FrameType.ERROR, {
                "status": "rejected",
                "reason": f"File size {format_bytes(expected_size)} exceeds allowed maximum of {format_bytes(self.max_file_size)}."
            })
            return

        safe_filename = sanitize_filename(raw_filename)
        destination_path = (self.save_dir / safe_filename).resolve()

        # Enforce destination sandbox security check
        if not str(destination_path).startswith(str(self.save_dir)):
            send_json(client_sock, FrameType.ERROR, {
                "status": "rejected",
                "reason": "Security violation: directory traversal attempt blocked."
            })
            return

        # Handle duplicate filenames with timestamp
        if destination_path.exists():
            stem = destination_path.stem
            suffix = destination_path.suffix
            destination_path = self.save_dir / f"{stem}_{int(time.time())}{suffix}"

        send_json(client_sock, FrameType.ACK, {"status": "ready_for_chunks"})

        start_time = time.time()
        received_bytes = 0

        try:
            with open(destination_path, "wb") as f:
                while received_bytes < expected_size:
                    frame_type, chunk_data = recv_frame(client_sock)
                    if frame_type == FrameType.FILE_CHUNK:
                        f.write(chunk_data)
                        received_bytes += len(chunk_data)
                    elif frame_type == FrameType.FILE_END:
                        break
                    else:
                        raise ValueError(f"Unexpected frame during transfer: {frame_type}")

            duration = max(time.time() - start_time, 0.0001)
            actual_sha256 = compute_file_sha256(str(destination_path)).lower()
            integrity_verified = (actual_sha256 == expected_sha256)

            speed_str = format_speed(received_bytes, duration)
            logger.info(
                f"File '{destination_path.name}' received from {client_ip}. "
                f"Size: {format_bytes(received_bytes)}, Duration: {duration:.2f}s, Speed: {speed_str}, "
                f"SHA-256 Match: {integrity_verified}"
            )

            result_info = {
                "status": "completed" if integrity_verified else "corrupted",
                "filename": destination_path.name,
                "saved_path": str(destination_path),
                "bytes_transferred": received_bytes,
                "duration_seconds": round(duration, 3),
                "speed": speed_str,
                "sender_ip": client_ip,
                "receiver_ip": self.host,
                "integrity_verified": integrity_verified,
                "expected_sha256": expected_sha256,
                "actual_sha256": actual_sha256
            }

            self._emit_event("file_transfer_completed", result_info)

            send_json(client_sock, FrameType.ACK, {
                "status": "completed" if integrity_verified else "hash_mismatch",
                "integrity_verified": integrity_verified,
                "received_bytes": received_bytes,
                "duration_seconds": round(duration, 3),
                "speed": speed_str,
                "actual_sha256": actual_sha256
            })

        except Exception as e:
            logger.error(f"File transfer failed: {e}")
            if destination_path.exists():
                try:
                    destination_path.unlink()
                except Exception:
                    pass
            send_json(client_sock, FrameType.ERROR, {"status": "failed", "reason": str(e)})


def run_standalone_receiver(host: str = "0.0.0.0", port: int = 65432, save_dir: Optional[str] = None):
    """Entrypoint for running the receiver directly from the terminal."""
    server = ReceiverServer(host=host, port=port, save_dir=save_dir)
    server.start()
    print("=" * 65)
    print("🚀 NetVision TCP Receiver Server Running")
    print(f"📡 Listening Interface: {host}:{port}")
    print(f"📁 Destination Folder: {server.save_dir}")
    print("Press Ctrl+C to shut down.")
    print("=" * 65)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping NetVision Receiver...")
        server.stop()
        print("Receiver stopped.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="NetVision TCP Receiver Server")
    parser.add_argument("--host", default="0.0.0.0", help="IP address to bind (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=65432, help="Port to listen on (default: 65432)")
    parser.add_argument("--dir", default=None, help="Directory to save received files")
    args = parser.parse_args()

    run_standalone_receiver(host=args.host, port=args.port, save_dir=args.dir)
