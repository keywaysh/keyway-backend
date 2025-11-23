#!/bin/bash

# Test du Device Flow OAuth complet pour Keyway
# Usage: ./test-device-flow.sh

set -e

API_URL="http://localhost:3000"

echo "🔐 Keyway Device Flow Test"
echo "======================================"
echo ""

# Step 1: Start device flow
echo "📝 Step 1: Starting device flow..."
RESPONSE=$(curl -s -X POST "$API_URL/auth/device/start")
echo "$RESPONSE" | jq .

# Extract codes
DEVICE_CODE=$(echo "$RESPONSE" | jq -r '.deviceCode')
USER_CODE=$(echo "$RESPONSE" | jq -r '.userCode')
VERIFICATION_URI=$(echo "$RESPONSE" | jq -r '.verificationUri')
VERIFICATION_URI_COMPLETE=$(echo "$RESPONSE" | jq -r '.verificationUriComplete')
INTERVAL=$(echo "$RESPONSE" | jq -r '.interval')

echo ""
echo "======================================"
echo "✅ Device flow started!"
echo "======================================"
echo ""
echo "🔑 User Code: $USER_CODE"
echo "🌐 Verification URL: $VERIFICATION_URI"
echo "📱 Or use direct link: $VERIFICATION_URI_COMPLETE"
echo ""
echo "======================================"
echo "⚠️  ACTION REQUIRED:"
echo "======================================"
echo ""
echo "1. Open this URL in your browser:"
echo "   $VERIFICATION_URI"
echo ""
echo "2. Enter the code: $USER_CODE"
echo ""
echo "3. Authenticate with GitHub"
echo ""
echo "======================================"
echo ""
read -p "Press ENTER after completing authentication in browser..."

# Step 2: Poll for approval
echo ""
echo "⏳ Step 2: Polling for approval..."
MAX_ATTEMPTS=60
ATTEMPT=0

while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
  ATTEMPT=$((ATTEMPT + 1))
  echo "   Poll attempt $ATTEMPT/$MAX_ATTEMPTS..."

  POLL_RESPONSE=$(curl -s -X POST "$API_URL/auth/device/poll" \
    -H "Content-Type: application/json" \
    -d "{\"deviceCode\":\"$DEVICE_CODE\"}")

  STATUS=$(echo "$POLL_RESPONSE" | jq -r '.status')

  if [ "$STATUS" = "approved" ]; then
    echo ""
    echo "======================================"
    echo "✅ Authentication successful!"
    echo "======================================"
    echo ""
    echo "$POLL_RESPONSE" | jq .

    # Extract token
    KEYWAY_TOKEN=$(echo "$POLL_RESPONSE" | jq -r '.keywayToken')
    GITHUB_LOGIN=$(echo "$POLL_RESPONSE" | jq -r '.githubLogin')
    EXPIRES_AT=$(echo "$POLL_RESPONSE" | jq -r '.expiresAt')

    echo ""
    echo "======================================"
    echo "📋 Token Information:"
    echo "======================================"
    echo "GitHub Login: $GITHUB_LOGIN"
    echo "Expires At: $EXPIRES_AT"
    echo "Token (first 50 chars): ${KEYWAY_TOKEN:0:50}..."
    echo ""

    # Step 3: Test token with API
    echo "======================================"
    echo "🧪 Step 3: Testing token with API..."
    echo "======================================"
    echo ""

    echo "Testing /health endpoint with JWT token..."
    HEALTH_RESPONSE=$(curl -s "$API_URL/health" \
      -H "Authorization: Bearer $KEYWAY_TOKEN")
    echo "$HEALTH_RESPONSE" | jq .

    echo ""
    echo "======================================"
    echo "✅ All tests passed!"
    echo "======================================"
    echo ""
    echo "🎉 Your Keyway token is ready to use!"
    echo ""
    echo "Save this token in your CLI config:"
    echo "$KEYWAY_TOKEN"
    echo ""

    exit 0
  elif [ "$STATUS" = "pending" ]; then
    sleep "$INTERVAL"
  elif [ "$STATUS" = "expired" ]; then
    echo ""
    echo "❌ Device code expired. Please restart the flow."
    echo "$POLL_RESPONSE" | jq .
    exit 1
  elif [ "$STATUS" = "denied" ]; then
    echo ""
    echo "❌ Authentication denied by user."
    echo "$POLL_RESPONSE" | jq .
    exit 1
  else
    echo ""
    echo "❌ Unexpected status: $STATUS"
    echo "$POLL_RESPONSE" | jq .
    exit 1
  fi
done

echo ""
echo "❌ Timeout waiting for authentication"
exit 1
