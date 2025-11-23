# 🔐 Device Flow OAuth - Guide complet

Ce document explique le flow d'authentification OAuth Device Flow implémenté pour Keyway CLI.

## 📋 Vue d'ensemble

Le **Device Flow** est un flow OAuth conçu pour les applications **sans navigateur intégré** (CLI, IoT, TV apps). Il permet à un utilisateur d'autoriser une application via un navigateur séparé.

### ✨ Améliorations UX

- ✅ **Auto-ouverture du browser** avec code pré-rempli
- ✅ **Auto-submit après 2 secondes** (l'utilisateur peut annuler)
- ✅ **Spinner de chargement** pendant la redirection
- ✅ **Pages HTML stylées** pour toutes les étapes
- ✅ **Polling intelligent** avec indicateur de progression

## 🔄 Flow complet

```
┌─────────────┐
│  Keyway CLI │
└──────┬──────┘
       │
       │ 1. POST /auth/device/start
       ├────────────────────────────────►┌──────────────────┐
       │                                  │   Keyway API     │
       │◄────────────────────────────────┤                  │
       │  deviceCode, userCode, URI       └──────────────────┘
       │
       │ 2. Ouvre browser automatiquement
       │    avec verificationUriComplete
       │
       ├──────────►┌──────────────────┐
       │            │   Browser        │
       │            │                  │
       │            │  🔐 Enter code   │
       │            │  [B339-MNPH]     │  Auto-submit après 2s
       │            │                  │────┐
       │            │  [Continue ▶]    │    │
       │            └──────────────────┘    │
       │                                    │ 3. POST /auth/device/verify
       │                                    │    avec user_code
       │                                    │
       │                                    ▼
       │            ┌──────────────────────────────────┐
       │            │  Redirection vers GitHub OAuth   │
       │            │                                  │
       │            │  github.com/login/oauth/authorize│
       │            │                                  │
       │            │  "Authorize keyway-backend?"     │
       │            │                                  │
       │            │  [Authorize ▶]                   │
       │            └──────────────────────────────────┘
       │                                    │
       │                                    │ 4. User clicks Authorize
       │                                    │
       │                                    ▼
       │            ┌──────────────────────────────────┐
       │            │  GET /auth/device/callback       │
       │            │                                  │
       │            │  - Exchange code for token       │
       │            │  - Create/update user in DB      │
       │            │  - Mark device code as approved  │
       │            │                                  │
       │            │  ✅ Success page                 │
       │            └──────────────────────────────────┘
       │
       │ 5. Poll toutes les 5 secondes
       │    POST /auth/device/poll
       ├────────────────────────────────►┌──────────────────┐
       │                                  │   Keyway API     │
       │◄────────────────────────────────┤                  │
       │  {"status": "pending"}           └──────────────────┘
       │
       │    ... poll ...
       │
       ├────────────────────────────────►┌──────────────────┐
       │                                  │   Keyway API     │
       │◄────────────────────────────────┤                  │
       │  {"status": "approved",          └──────────────────┘
       │   "keywayToken": "eyJhbG...",
       │   "githubLogin": "username"}
       │
       │ 6. ✅ Token reçu !
       │    Sauvegarde dans config
       │
       ▼
   [Authenticated]
```

## 🧪 Tests

### Option 1 : Script automatique (recommandé)

```bash
# Le serveur doit tourner sur localhost:3000
./test-device-flow-auto.sh
```

**Ce que fait le script :**
1. ✅ Appelle `/auth/device/start`
2. 🌐 Ouvre automatiquement le browser avec le code pré-rempli
3. ⏳ Poll l'API toutes les 5 secondes
4. 🎉 Affiche le token une fois reçu

### Option 2 : Test manuel

```bash
# 1. Start device flow
curl -X POST http://localhost:3000/auth/device/start | jq .

# Response:
{
  "deviceCode": "abc123...",
  "userCode": "B339-MNPH",
  "verificationUri": "http://localhost/auth/device/verify",
  "verificationUriComplete": "http://localhost/auth/device/verify?user_code=B339-MNPH",
  "expiresIn": 900,
  "interval": 5
}

# 2. Ouvrir l'URL (macOS)
open "http://localhost:3000/auth/device/verify?user_code=B339-MNPH"

# 3. Poll (dans un autre terminal)
while true; do
  curl -s -X POST http://localhost:3000/auth/device/poll \
    -H "Content-Type: application/json" \
    -d '{"deviceCode":"abc123..."}' | jq .
  sleep 5
done
```

## 📡 API Endpoints

### POST /auth/device/start

**Démarre le device flow.**

**Request:** Aucun body requis

**Response:**
```json
{
  "deviceCode": "64-char-hex-string",
  "userCode": "B339-MNPH",
  "verificationUri": "https://api.keyway.sh/auth/device/verify",
  "verificationUriComplete": "https://api.keyway.sh/auth/device/verify?user_code=B339-MNPH",
  "expiresIn": 900,
  "interval": 5
}
```

### POST /auth/device/poll

**Poll le statut d'authorization.**

**Request:**
```json
{
  "deviceCode": "64-char-hex-string"
}
```

**Response (pending):**
```json
{
  "status": "pending"
}
```

**Response (approved):**
```json
{
  "status": "approved",
  "keywayToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "githubLogin": "username",
  "expiresAt": "2025-12-23T20:49:07.000Z"
}
```

**Response (expired - 400):**
```json
{
  "status": "expired",
  "message": "The device code has expired. Please restart the authentication flow."
}
```

**Response (denied - 403):**
```json
{
  "status": "denied",
  "message": "User denied the authorization request."
}
```

### GET /auth/device/verify

**Page HTML de vérification.**

**Query params:**
- `user_code` (optional) - Si fourni, le code est pré-rempli et le formulaire s'auto-submit après 2 secondes

**Features:**
- ✅ Code pré-rempli si fourni dans l'URL
- ✅ Auto-submit après 2 secondes (peut être annulé)
- ✅ Spinner de chargement
- ✅ Countdown visible

### POST /auth/device/verify

**Vérifie le code et redirige vers GitHub OAuth.**

**Form data:**
- `user_code` - Le code à vérifier (format: XXXX-XXXX)

**Behavior:**
- Vérifie que le code existe et n'est pas expiré
- Redirige vers `https://github.com/login/oauth/authorize`
- Passe l'ID du device code dans le paramètre `state` (encodé en base64)

### GET /auth/device/callback

**Callback GitHub OAuth.**

**Query params:**
- `code` - Authorization code de GitHub
- `state` - État contenant l'ID du device code

**Behavior:**
- Exchange le code GitHub pour un access token
- Crée ou met à jour l'utilisateur dans la DB
- Marque le device code comme `approved`
- Affiche une page de succès

## 🔐 Sécurité

### Device Code
- **Format:** 64 caractères hexadécimaux
- **Génération:** `crypto.randomBytes(32).toString('hex')`
- **Unique:** Index unique en DB

### User Code
- **Format:** XXXX-XXXX (8 chars)
- **Caractères:** A-Z, 2-9 (pas de 0, O, 1, I, L pour éviter confusion)
- **Génération:** Cryptographiquement sécurisé avec `crypto.randomInt()`
- **Unique:** Index unique en DB

### JWT Tokens
- **Algorithme:** HS256
- **Expiration:** 30 jours
- **Payload:** `{ userId, githubId, username }`
- **Secret:** `JWT_SECRET` dans `.env` (min 32 chars)

### Expiration
- **Device codes:** 15 minutes (`expiresAt` timestamp)
- **JWT tokens:** 30 jours
- **Nettoyage:** Les device codes expirés sont automatiquement détectés lors du poll

## 🎯 Exemple d'intégration CLI

Voir `example-cli-flow.ts` pour un exemple complet d'intégration dans Keyway CLI.

**Usage simple:**

```typescript
import { loginWithDeviceFlow } from './auth';

// Dans la commande `keyway login`
const token = await loginWithDeviceFlow();

// Sauvegarder le token
await saveTokenToConfig(token);

console.log('✅ Logged in successfully!');
```

## 🎨 UX Flow

### Avant (sans auto-submit)
1. CLI affiche le code
2. User ouvre le browser manuellement
3. User **tape le code manuellement**
4. User clique "Continue with GitHub"
5. User authorise sur GitHub
6. User revient à la CLI

**Total: 6 étapes**

### Après (avec auto-submit) ✅
1. CLI ouvre le browser automatiquement
2. **Page auto-submit après 2s** (code déjà rempli)
3. User clique "Authorize" sur GitHub
4. User revient à la CLI

**Total: 4 étapes** → **33% de réduction !**

## 📊 Compatibilité

- ✅ macOS (commande `open`)
- ✅ Linux (commande `xdg-open`)
- ✅ Windows (commande `start`)
- ✅ Fallback manuel si auto-open échoue

## 🐛 Debugging

```bash
# Voir les logs du serveur
pnpm dev

# Tester uniquement le start
curl -X POST http://localhost:3000/auth/device/start | jq .

# Tester le poll
curl -X POST http://localhost:3000/auth/device/poll \
  -H "Content-Type: application/json" \
  -d '{"deviceCode":"YOUR_DEVICE_CODE"}' | jq .

# Voir la page de vérification
open "http://localhost:3000/auth/device/verify?user_code=TEST-CODE"
```

## 🔮 Améliorations futures

- [ ] Support pour `keyway login --token` (PAT direct)
- [ ] Refresh tokens automatiques
- [ ] Revoke tokens endpoint
- [ ] QR code pour mobile
- [ ] Multiple sessions
- [ ] Session management dashboard
