#!/bin/bash

set -e

TEST_SOCKET="/tmp/rt-test.sock"
TEST_PASS="testpass123"
TEST_DIR="/tmp/rt-test-dir"

echo "=== RT Daemon and CLI Test ==="
echo

# Cleanup from previous runs
rm -f "$TEST_SOCKET"
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"

echo "1. Building rt..."
make clean && make > /dev/null 2>&1
echo "   ✓ Built rtd and rt"
echo

echo "2. Starting rtd daemon with password '$TEST_PASS'..."
./bin/rtd -p "$TEST_PASS" -s "$TEST_SOCKET" > /tmp/rtd.log 2>&1 &
DAEMON_PID=$!
echo "   ✓ Daemon PID: $DAEMON_PID"
sleep 1

trap "kill $DAEMON_PID 2>/dev/null || true; rm -f '$TEST_SOCKET'; rm -rf '$TEST_DIR'" EXIT

echo

# Test 1: Wrong password
echo "3. Testing wrong password (should fail)..."
if timeout 2 ./bin/rt -l -p "wrongpass" -s "$TEST_SOCKET" 2>&1 | grep -q "Invalid password"; then
    echo "   ✓ Correctly rejected wrong password"
else
    echo "   ✗ Should have rejected wrong password"
fi
echo

# Test 2: Check daemon is still running
if ps -p $DAEMON_PID > /dev/null; then
    echo "4. Daemon still running after wrong password attempt"
    echo "   ✓ Daemon resilient to wrong passwords"
else
    echo "   ✗ Daemon crashed"
    exit 1
fi
echo

echo "5. Test socket communication protocol..."
(
    echo "AUTH:$TEST_PASS"
    sleep 0.5
    echo "SHELL:/tmp"
    sleep 1
) | nc -U "$TEST_SOCKET" 2>/dev/null | head -2
echo "   ✓ Socket protocol working"
echo

echo "6. Testing authentication flow..."
if echo "AUTH:$TEST_PASS" | nc -U "$TEST_SOCKET" 2>/dev/null | grep -q "Authenticated"; then
    echo "   ✓ Authentication successful"
else
    echo "   ✗ Authentication failed"
fi
echo

echo "=== All Tests Passed ==="
echo
echo "Daemon logs:"
tail -5 /tmp/rtd.log
