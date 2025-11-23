#!/bin/bash

# Configuration
API_URL="https://keyway-backend-production.up.railway.app"
GITHUB_TOKEN="ton_github_token_ici"  # À remplacer
REPO="ton-username/ton-repo"          # À remplacer

echo "🔍 Test 1: Health Check"
curl -s "$API_URL/health" | jq
echo ""

echo "🔐 Test 2: Init Vault"
curl -s -X POST "$API_URL/vaults/init" \
  -H "Content-Type: application/json" \
  -d "{
    \"repoFullName\": \"$REPO\",
    \"accessToken\": \"$GITHUB_TOKEN\"
  }" | jq
echo ""

echo "📤 Test 3: Push Secrets"
curl -s -X POST "$API_URL/vaults/$REPO/production/push" \
  -H "Content-Type: application/json" \
  -d "{
    \"content\": \"DATABASE_URL=postgresql://test\\nAPI_KEY=secret123\",
    \"accessToken\": \"$GITHUB_TOKEN\"
  }" | jq
echo ""

echo "📥 Test 4: Pull Secrets"
curl -s "$API_URL/vaults/$REPO/production/pull?accessToken=$GITHUB_TOKEN" | jq
echo ""

echo "✅ Tests terminés!"
