"""
Integration Tests for NetVision TCP Sender and Receiver
Tests connection lifecycle, message transfer, RTT ping, and connection failure handling.
"""

import time
import pytest
from network.receiver import ReceiverServer
from network.sender import SenderClient


@pytest.fixture(scope="module")
def active_receiver():
    """Start a real receiver server on localhost for automated integration testing."""
    test_port = 64123
    server = ReceiverServer(host="127.0.0.1", port=test_port)
    server.start()
    time.sleep(0.2)  # Allow socket bind
    yield test_port
    server.stop()
    time.sleep(0.2)


def test_tcp_connection_and_ping(active_receiver):
    """Test 1: TCP connection establishment and RTT measurement."""
    client = SenderClient(target_host="127.0.0.1", target_port=active_receiver, timeout=3.0)
    res = client.test_connection()
    assert res["status"] == "connected"
    assert "rtt_ms" in res
    assert res["rtt_ms"] >= 0.0


def test_text_message_transfer(active_receiver):
    """Test 2: Text message framing, delivery, and ACK verification."""
    client = SenderClient(target_host="127.0.0.1", target_port=active_receiver, timeout=3.0)
    msg = "NetVision Automated DCCN Unit Test Message"
    res = client.send_message(msg)

    assert res["status"] == "success"
    assert res["bytes_sent"] == len(msg.encode("utf-8"))
    assert res["ack"]["status"] == "success"
    assert "Message received successfully" in res["ack"]["message"]
    assert res["duration_seconds"] > 0.0


def test_connection_failure_handling():
    """Test 3: Graceful error handling when connecting to inactive port."""
    inactive_port = 64999
    client = SenderClient(target_host="127.0.0.1", target_port=inactive_port, timeout=1.0)
    with pytest.raises((ConnectionRefusedError, TimeoutError)):
        client.send_message("This should fail cleanly")
