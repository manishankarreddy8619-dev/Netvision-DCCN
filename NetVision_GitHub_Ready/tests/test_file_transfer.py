"""
Unit & Integration Tests for NetVision Binary File Transfer
Tests SHA-256 hash verification, path traversal defense, and speed calculation.
"""

import os
import tempfile
import time
import pytest
from network.receiver import ReceiverServer
from network.sender import SenderClient
from network.file_transfer import (
    compute_file_sha256,
    sanitize_filename,
    format_bytes,
    format_speed
)


@pytest.fixture(scope="module")
def file_transfer_env():
    """Setup receiver server and temporary directory for file transfer tests."""
    temp_dir = tempfile.mkdtemp()
    test_port = 64124
    server = ReceiverServer(host="127.0.0.1", port=test_port, save_dir=temp_dir)
    server.start()
    time.sleep(0.2)
    yield test_port, temp_dir
    server.stop()
    time.sleep(0.2)


def test_filename_sanitization_and_path_traversal():
    """Test security sanitization against directory traversal exploits."""
    assert sanitize_filename("../../../etc/passwd") == "passwd"
    assert sanitize_filename("..\\..\\Windows\\System32\\cmd.exe") == "cmd.exe"
    assert sanitize_filename("normal_file.txt") == "normal_file.txt"
    assert sanitize_filename("malicious*file?.bin") == "malicious_file_.bin"


def test_binary_file_transfer_and_sha256_integrity(file_transfer_env):
    """Test sending a binary file and verifying SHA-256 match."""
    port, save_dir = file_transfer_env

    # Create dummy binary test file (128 KB of deterministic bytes)
    sample_data = b"NetVision-Binary-Test-Payload-" * 4096
    with tempfile.NamedTemporaryFile(delete=False, suffix=".dat") as f:
        f.write(sample_data)
        src_path = f.name

    try:
        expected_hash = compute_file_sha256(src_path)

        client = SenderClient(target_host="127.0.0.1", target_port=port)
        result = client.send_file(src_path)

        assert result["status"] == "completed"
        assert result["integrity_verified"] is True
        assert result["local_sha256"] == expected_hash
        assert result["remote_sha256"] == expected_hash
        assert result["bytes_transferred"] == len(sample_data)
        assert result["duration_seconds"] > 0.0

        # Verify destination file on receiver disk
        dest_path = os.path.join(save_dir, os.path.basename(src_path))
        assert os.path.exists(dest_path)
        with open(dest_path, "rb") as df:
            assert df.read() == sample_data
    finally:
        if os.path.exists(src_path):
            os.remove(src_path)


def test_formatting_utilities():
    """Test byte and speed calculation formatters."""
    assert format_bytes(500) == "500.0 B"
    assert format_bytes(2048) == "2.0 KB"
    assert format_bytes(5 * 1024 * 1024) == "5.0 MB"
    assert "MB/s" in format_speed(10 * 1024 * 1024, 2.0)
