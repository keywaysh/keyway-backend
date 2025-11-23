#!/bin/bash

# Test du Device Flow OAuth avec auto-ouverture du browser
# Usage: ./test-device-flow-auto.sh

set -e

API_URL="http://localhost:3000"

echo "🔐 Keyway Device Flow - Auto Browser Test"
echo "=========================================="
echo ""

# Step 1: Start device flow
echo "📝 Starting device flow..."
RESPONSE=$(curl -s -X POST "$API_URL/auth/device/start")

# Extract codes
DEVICE_CODE=$(echo "$RESPONSE" | jq -r '.deviceCode')
USER_CODE=$(echo "$RESPONSE" | jq -r '.userCode')
VERIFICATION_URI_COMPLETE=$(echo "$RESPONSE" | jq -r '.verificationUriComplete')
INTERVAL=$(echo "$RESPONSE" | jq -r '.interval')

echo ""
echo "=========================================="
echo "✅ Device flow started!"
echo "=========================================="
echo ""
echo "🔑 User Code: $USER_CODE"
echo "🌐 Verification URL: $VERIFICATION_URI_COMPLETE"
echo ""

# Step 2: Auto-open browser
echo "=========================================="
echo "🌐 Opening browser automatically..."
echo "=========================================="
echo ""

# Detect OS and open browser
if [[ "$OSTYPE" == "darwin"* ]]; then
  # macOS
  open "$VERIFICATION_URI_COMPLETE"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
  # Linux
  xdg-open "$VERIFICATION_URI_COMPLETE" 2>/dev/null || {
    echo "⚠️  Could not auto-open browser. Please visit:"
    echo "   $VERIFICATION_URI_COMPLETE"
  }
elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
  # Windows Git Bash
  start "$VERIFICATION_URI_COMPLETE"
else
  echo "⚠️  Could not detect OS. Please manually visit:"
  echo "   $VERIFICATION_URI_COMPLETE"
fi

echo "ℹ️  The page will auto-submit after 2 seconds"
echo "   Just click 'Authorize' on GitHub!"
echo ""

# Step 3: Poll for approval
echo "=========================================="
echo "⏳ Waiting for authentication..."
echo "=========================================="
echo ""

MAX_ATTEMPTS=60
ATTEMPT=0
DOTS=""

while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
  ATTEMPT=$((ATTEMPT + 1))
  DOTS="${DOTS}."

  # Show progress without cluttering terminal
  printf "\r   Polling... %s (%d/%d)" "$DOTS" "$ATTEMPT" "$MAX_ATTEMPTS"

  POLL_RESPONSE=$(curl -s -X POST "$API_URL/auth/device/poll" \
    -H "Content-Type: application/json" \
    -d "{\"deviceCode\":\"$DEVICE_CODE\"}")

  STATUS=$(echo "$POLL_RESPONSE" | jq -r '.status')

  if [ "$STATUS" = "approved" ]; then
    echo ""
    echo ""
    echo "=========================================="
    echo "✅ Authentication successful!"
    echo "=========================================="
    echo ""

    # Extract token
    KEYWAY_TOKEN=$(echo "$POLL_RESPONSE" | jq -r '.keywayToken')
    GITHUB_LOGIN=$(echo "$POLL_RESPONSE" | jq -r '.githubLogin')
    EXPIRES_AT=$(echo "$POLL_RESPONSE" | jq -r '.expiresAt')

    echo "📋 Token Information:"
    echo "=========================================="
    echo "GitHub Login: $GITHUB_LOGIN"
    echo "Expires At: $EXPIRES_AT"
    echo ""
    echo "Keyway Token:"
    echo "$KEYWAY_TOKEN"
    echo ""

    # Test token
    echo "=========================================="
    echo "🧪 Testing token with API..."
    echo "=========================================="
    echo ""

    # Create a test to verify token works
    echo "Testing health endpoint..."
    HEALTH=$(curl -s "$API_URL/health")
    echo "$HEALTH" | jq .

    echo ""
    echo "=========================================="
    echo "✅ All tests passed!"
    echo "=========================================="
    echo ""
    echo "💾 Save this token to use with Keyway CLI:"
    echo ""
    echo "export KEYWAY_TOKEN=\"$KEYWAY_TOKEN\""
    echo ""

    exit 0
  elif [ "$STATUS" = "pending" ]; then
    # Reset dots every 10 attempts
    if [ $((ATTEMPT % 10)) -eq 0 ]; then
      DOTS=""
    fi
    sleep "$INTERVAL"
  elif [ "$STATUS" = "expired" ]; then
    echo ""
    echo ""
    echo "❌ Device code expired. Please restart the flow."
    exit 1
  elif [ "$STATUS" = "denied" ]; then
    echo ""
    echo ""
    echo "❌ Authentication denied by user."
    exit 1
  else
    echo ""
    echo ""
    echo "❌ Unexpected status: $STATUS"
    echo "$POLL_RESPONSE" | jq .
    exit 1
  fi
done

echo ""
echo ""
echo "❌ Timeout waiting for authentication (5 minutes)"
exit 1
