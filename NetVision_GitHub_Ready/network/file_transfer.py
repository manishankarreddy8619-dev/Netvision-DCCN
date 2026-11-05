"""
NetVision - Network Framing & File Transfer Protocol Utilities
Handles binary framing, socket stream synchronization, SHA-256 integrity,
and security sanitization against path traversal attacks.
"""

import os
import re
import socket
import struct
import hashlib
import time
from enum import IntEnum
from typing import Tuple, Optional, Dict, Any
import json

MAGIC_BYTES = b"NV"
HEADER_FORMAT = "!2sHI"  # 2 bytes Magic, 2 bytes Type, 4 bytes Length (8 bytes total)
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
DEFAULT_BUFFER_SIZE = 64 * 1024  # 64 KB chunk size
MAX_ALLOWED_FILE_SIZE = 200 * 1024 * 1024  # 200 MB safe limit


class FrameType(IntEnum):
    MSG = 1
    FILE_META = 2
    FILE_CHUNK = 3
    FILE_END = 4
    ACK = 5
    ERROR = 6
    PING = 7
    PONG = 8


def send_exact(sock: socket.socket, data: bytes) -> None:
    """Send all bytes over socket, handling partial writes."""
    total_sent = 0
    while total_sent < len(data):
        sent = sock.send(data[total_sent:])
        if sent == 0:
            raise ConnectionResetError("Socket connection broken during send")
        total_sent += sent


def recv_exact(sock: socket.socket, num_bytes: int) -> bytes:
    """Read exactly num_bytes from socket, handling TCP streaming chunks."""
    buf = bytearray()
    while len(buf) < num_bytes:
        packet = sock.recv(num_bytes - len(buf))
        if not packet:
            if len(buf) == 0:
                raise ConnectionResetError("Connection closed by remote host")
            raise ConnectionResetError(f"Unexpected EOF: expected {num_bytes} bytes, received {len(buf)} bytes")
        buf.extend(packet)
    return bytes(buf)


def send_frame(sock: socket.socket, frame_type: FrameType, payload: bytes = b"") -> None:
    """Encapsulate and send a length-prefixed frame."""
    header = struct.pack(HEADER_FORMAT, MAGIC_BYTES, int(frame_type), len(payload))
    send_exact(sock, header + payload)


def recv_frame(sock: socket.socket) -> Tuple[FrameType, bytes]:
    """Receive and unpack the next frame from the stream."""
    header_bytes = recv_exact(sock, HEADER_SIZE)
    magic, raw_type, payload_len = struct.unpack(HEADER_FORMAT, header_bytes)

    if magic != MAGIC_BYTES:
        raise ValueError(f"Invalid frame magic bytes: {magic!r}. Protocol desynchronized.")

    try:
        frame_type = FrameType(raw_type)
    except ValueError:
        raise ValueError(f"Unknown frame type identifier: {raw_type}")

    payload = recv_exact(sock, payload_len)
    return frame_type, payload


def send_json(sock: socket.socket, frame_type: FrameType, data: Dict[str, Any]) -> None:
    """Serialize dictionary as JSON and transmit frame."""
    payload = json.dumps(data).encode("utf-8")
    send_frame(sock, frame_type, payload)


def recv_json(sock: socket.socket, expected_type: Optional[FrameType] = None) -> Tuple[FrameType, Dict[str, Any]]:
    """Receive frame and deserialize JSON payload."""
    frame_type, payload = recv_frame(sock)
    if expected_type is not None and frame_type != expected_type:
        raise ValueError(f"Expected frame type {expected_type.name}, got {frame_type.name}")
    try:
        data = json.loads(payload.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"Failed to decode JSON payload: {e}")
    return frame_type, data


def compute_file_sha256(filepath: str) -> str:
    """Compute SHA-256 hash of a file efficiently using streaming blocks."""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(DEFAULT_BUFFER_SIZE):
            hasher.update(chunk)
    return hasher.hexdigest()


def compute_bytes_sha256(data: bytes) -> str:
    """Compute SHA-256 hash of byte buffer."""
    return hashlib.sha256(data).hexdigest()


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent directory traversal and path manipulation attacks.
    Ensures safe handling on Windows, Linux, and macOS.
    """
    # Extract basename only (strips any ../ or c:\ path elements)
    base = os.path.basename(filename.strip().replace("\\", "/"))
    # Replace dangerous characters with underscore
    safe = re.sub(r'[^a-zA-Z0-9_.\-]', '_', base)
    if not safe or safe in (".", ".."):
        safe = f"transfer_{int(time.time())}.bin"
    return safe


def format_bytes(num_bytes: int) -> str:
    """Human-readable byte size format."""
    for unit in ["B", "KB", "MB", "GB"]:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:3.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} TB"


def format_speed(bytes_transferred: int, duration_sec: float) -> str:
    """Calculate and format transfer speed (B/s, KB/s, MB/s)."""
    if duration_sec <= 0.0001:
        return "N/A (instant)"
    bytes_per_sec = bytes_transferred / duration_sec
    return f"{format_bytes(bytes_per_sec)}/s"
