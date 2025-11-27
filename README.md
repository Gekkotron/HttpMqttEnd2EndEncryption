# End-to-End Encryption Gateway

A secure, production-ready gateway server that provides end-to-end encryption for Jeedom API and MQTT communications using AES-GCM encryption. Protect your smart home communications with military-grade encryption while maintaining ease of use.

## Features

- **AES-GCM Encryption**: Military-grade end-to-end encryption for all requests and responses
- **Multi-Service Support**: Unified gateway for both Jeedom JSON-RPC API and MQTT broker communications
- **MQTT SSE Streaming**: Real-time MQTT topic subscriptions via Server-Sent Events over HTTP
- **Automatic Key Management**: Secure secret key generation on first launch
- **Replay Attack Protection**: Timestamp validation with configurable time windows
- **Docker Ready**: Complete containerization with Docker Compose support
- **Tailscale Funnel Integration**: Secure public internet exposure without port forwarding
- **Production Ready**: Comprehensive error handling, logging, and health checks
- **Extensive Testing**: Full test suite included for both Jeedom and MQTT services

## Architecture

```
┌─────────────┐    Encrypted     ┌─────────────────┐    Unencrypted    ┌──────────┐
│   Client    │ ───────────────> │  E2E Gateway    │ ────────────────> │  Jeedom  │
│ (Your App)  │ <─────────────── │   (This App)    │ <──────────────── │  Server  │
└─────────────┘    AES-GCM       └─────────────────┘                    └──────────┘
                                          │
                                          │ Unencrypted
                                          ↓
                                  ┌─────────────┐
                                  │ MQTT Broker │
                                  └─────────────┘
```

The gateway acts as a secure proxy, encrypting/decrypting traffic between your client applications and backend services (Jeedom and MQTT).

## Quick Start

### Prerequisites

- Python 3.9+ or Docker
- (Optional) Tailscale for secure internet exposure

### Installation

#### Option 1: Docker (Recommended for Production)

1. Clone the repository:
```bash
git clone <repository-url>
cd FullEndToEndEncryption
```

2. Configure environment (optional):
```bash
cp .env.example .env
# Edit .env to customize settings
```

3. Start with Docker Compose:
```bash
docker compose up -d
```

The server will start on port 10000 and automatically generate a secret key in `data/secret_key.txt`.

#### Option 2: Direct Python (Development)

1. Create and activate a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the server:
```bash
python -m server
```

### Secret Key Setup

On first launch, the server automatically generates a 256-bit AES secret key and displays it:

```
================================================================================
NEW SECRET KEY GENERATED!
================================================================================
Secret key: 3616864d6ed4f70b8a774e17c7435b411d8bc5714fddaf88e3850104a9d88ccd
Saved to: secret_key.txt
================================================================================
Please update your client with this secret key.
================================================================================
```

**Important**: Save this key securely and configure your clients with it.

## Configuration

### Environment Variables

You can configure the gateway using environment variables. Create a `.env` file in the project root:

```bash
cp .env.example .env
# Edit .env with your settings
```

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY_FILE` | `server/secret_key.txt` | Path to the secret key file |
| `JEEDOM_URL` | `http://localhost:80` | Your Jeedom server URL |
| `JEEDOM_APIKEY` | `` | Your Jeedom API key (for testing) |
| `MAX_AGE_SECONDS` | `60` | Maximum age for request timestamps (replay protection) |
| `HOST` | `0.0.0.0` | Server bind address |
| `PORT` | `10000` | Server port |
| `MQTT_BROKER_HOST` | `192.168.1.91` | Default MQTT broker hostname |
| `MQTT_BROKER_PORT` | `1883` | Default MQTT broker port |

### Docker Volumes

The Docker setup uses a persistent volume for the secret key:
- `./data:/app/data` - Stores the secret key across container restarts

## Usage

### Client Implementation

The project includes a ready-to-use Python client class for both Jeedom and MQTT:

#### Jeedom Example

```python
from test_client.client_jeedom_test import EncryptedClient

# Load secret key from file
with open('server/secret_key.txt', 'r') as f:
    SECRET_KEY = f.read().strip()

# Initialize client
client = EncryptedClient(
    gateway_url="http://localhost:10000",
    secret_key=SECRET_KEY,
    jeedom_apikey="your-jeedom-api-key"
)

# Make encrypted request (datetime method)
response = client.send_request(jsonrpc="datetime")

print(f"Status: {response['status']}")
print(f"Body: {response['body']}")
# Expected body format:
# {
#     "jsonrpc": "2.0",
#     "id": 99999,
#     "result": 1764197216.35285
# }
```

#### MQTT Publish Example

```python
from test_client.client_mqtt_test import EncryptedClient

# Initialize client
client = EncryptedClient(
    gateway_url="http://localhost:10000",
    secret_key=SECRET_KEY
)

# Publish encrypted message
response = client.send_mqtt(
    topic="home/temperature",
    message="22.5",
    qos=1,
    retain=True
)

print(f"Status: {response['status']}")
print(f"Body: {response['body']}")
```

#### MQTT Subscribe (SSE) Example

Subscribe to MQTT topics and receive messages in real-time via Server-Sent Events:

```python
from test_client.client_mqtt_sse_test import subscribe_to_mqtt_topic

# Subscribe to a topic
subscribe_to_mqtt_topic(
    server_url="http://localhost:10000",
    topic="home/sensors/#",  # Supports MQTT wildcards
    qos=1
)

# With custom broker settings
subscribe_to_mqtt_topic(
    server_url="http://localhost:10000",
    topic="home/temperature",
    broker_host="192.168.1.100",
    broker_port=1883,
    username="mqtt_user",
    password="mqtt_password",
    qos=1
)
```

The SSE stream will receive encrypted messages with the following types:
- **connected**: Successfully subscribed to the topic
- **message**: MQTT message received (includes topic, payload, qos, retain)
- **error**: An error occurred
- **disconnected**: Connection closed

#### Android Example (Kotlin)

For Android applications, you can implement the encrypted client using Kotlin:

```kotlin
import android.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class EncryptedGatewayClient(
    private val gatewayUrl: String,
    private val secretKey: String,
    private val jeedomApiKey: String? = null
) {
    private val client = OkHttpClient()
    private val keyBytes = hexStringToByteArray(secretKey)

    // Convert hex string to byte array
    private fun hexStringToByteArray(s: String): ByteArray {
        val len = s.length
        val data = ByteArray(len / 2)
        var i = 0
        while (i < len) {
            data[i / 2] = ((Character.digit(s[i], 16) shl 4) +
                          Character.digit(s[i + 1], 16)).toByte()
            i += 2
        }
        return data
    }

    // Encrypt data using AES-GCM
    private fun encrypt(data: JSONObject): ByteArray {
        val nonce = ByteArray(12)
        SecureRandom().nextBytes(nonce)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(keyBytes, "AES")
        val gcmSpec = GCMParameterSpec(128, nonce)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)

        val plaintext = data.toString().toByteArray(Charsets.UTF_8)
        val ciphertext = cipher.doFinal(plaintext)

        // Return nonce + ciphertext
        return nonce + ciphertext
    }

    // Decrypt data using AES-GCM
    private fun decrypt(data: ByteArray): JSONObject {
        val nonce = data.sliceArray(0..11)
        val ciphertext = data.sliceArray(12 until data.size)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(keyBytes, "AES")
        val gcmSpec = GCMParameterSpec(128, nonce)
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)

        val plaintext = cipher.doFinal(ciphertext)
        return JSONObject(String(plaintext, Charsets.UTF_8))
    }

    // Send encrypted Jeedom request
    suspend fun sendJeedomRequest(
        jsonrpc: String,
        params: JSONObject? = null
    ): JSONObject = withContext(Dispatchers.IO) {
        val payload = JSONObject().apply {
            put("service", "jeedom")
            put("apikey", jeedomApiKey)
            put("jsonrpc", jsonrpc)
            put("timestamp", System.currentTimeMillis() / 1000)
            if (params != null) {
                put("params", params)
            }
        }

        val encrypted = encrypt(payload)
        val encoded = Base64.encodeToString(encrypted, Base64.NO_WRAP)

        val requestBody = encoded.toRequestBody(
            "application/octet-stream".toMediaType()
        )

        val request = Request.Builder()
            .url("$gatewayUrl/gateway")
            .post(requestBody)
            .build()

        val response = client.newCall(request).execute()
        val responseData = response.body?.bytes()
            ?: throw Exception("Empty response")

        val decoded = Base64.decode(responseData, Base64.NO_WRAP)
        decrypt(decoded)
    }

    // Send encrypted MQTT request
    suspend fun sendMqttRequest(
        topic: String,
        message: String,
        qos: Int = 0,
        retain: Boolean = false,
        brokerHost: String? = null,
        brokerPort: Int? = null,
        username: String? = null,
        password: String? = null
    ): JSONObject = withContext(Dispatchers.IO) {
        val payload = JSONObject().apply {
            put("service", "mqtt")
            put("topic", topic)
            put("message", message)
            put("qos", qos)
            put("retain", retain)
            put("timestamp", System.currentTimeMillis() / 1000)
            if (brokerHost != null) put("broker_host", brokerHost)
            if (brokerPort != null) put("broker_port", brokerPort)
            if (username != null) put("username", username)
            if (password != null) put("password", password)
        }

        val encrypted = encrypt(payload)
        val encoded = Base64.encodeToString(encrypted, Base64.NO_WRAP)

        val requestBody = encoded.toRequestBody(
            "application/octet-stream".toMediaType()
        )

        val request = Request.Builder()
            .url("$gatewayUrl/gateway")
            .post(requestBody)
            .build()

        val response = client.newCall(request).execute()
        val responseData = response.body?.bytes()
            ?: throw Exception("Empty response")

        val decoded = Base64.decode(responseData, Base64.NO_WRAP)
        decrypt(decoded)
    }
}

// Usage example in an Activity or ViewModel
class MainActivity : AppCompatActivity() {
    private lateinit var client: EncryptedGatewayClient

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Initialize client
        client = EncryptedGatewayClient(
            gatewayUrl = "https://yourdevice.tail497f.ts.net",
            secretKey = "your-secret-key-here",
            jeedomApiKey = "your-jeedom-api-key"
        )

        // Make encrypted request
        lifecycleScope.launch {
            try {
                // Jeedom request - datetime method
                val response = client.sendJeedomRequest(jsonrpc = "datetime")

                Log.d("Gateway", "Status: ${response.getInt("status")}")
                val body = response.getJSONObject("body")
                Log.d("Gateway", "Body: $body")
                // Expected: {"jsonrpc": "2.0", "id": 99999, "result": 1764197216.35285}

                if (body.has("result")) {
                    Log.d("Gateway", "Datetime: ${body.getDouble("result")}")
                }

                // MQTT request
                val mqttResponse = client.sendMqttRequest(
                    topic = "home/temperature",
                    message = "22.5",
                    qos = 1,
                    retain = true
                )

                Log.d("Gateway", "MQTT Status: ${mqttResponse.getInt("status")}")

            } catch (e: Exception) {
                Log.e("Gateway", "Error: ${e.message}", e)
            }
        }
    }
}
```

**Android Dependencies (build.gradle.kts):**

```kotlin
dependencies {
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")
    // JSON is included in Android SDK
}
```

**Required Permissions (AndroidManifest.xml):**

```xml
<uses-permission android:name="android.permission.INTERNET" />
```

**Security Best Practices for Android:**

1. **Store the secret key securely** using Android's EncryptedSharedPreferences:

```kotlin
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

fun saveSecretKey(context: Context, secretKey: String) {
    val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    val sharedPreferences = EncryptedSharedPreferences.create(
        context,
        "secure_prefs",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    sharedPreferences.edit().putString("secret_key", secretKey).apply()
}

fun getSecretKey(context: Context): String? {
    val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    val sharedPreferences = EncryptedSharedPreferences.create(
        context,
        "secure_prefs",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    return sharedPreferences.getString("secret_key", null)
}
```

2. **Add ProGuard/R8 rules** to protect sensitive code (proguard-rules.pro):

```proguard
# Keep encryption classes
-keep class javax.crypto.** { *; }
-keep class javax.crypto.spec.** { *; }
-keep class your.package.EncryptedGatewayClient { *; }
```

3. **Use certificate pinning** for production to prevent man-in-the-middle attacks:

```kotlin
import okhttp3.CertificatePinner

val certificatePinner = CertificatePinner.Builder()
    .add("yourdevice.tail497f.ts.net", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    .build()

private val client = OkHttpClient.Builder()
    .certificatePinner(certificatePinner)
    .build()
```

### Request Format

All requests must include:

```json
{
    "service": "jeedom|mqtt",
    "timestamp": 1234567890,
    // Service-specific fields...
}
```

#### Jeedom Request Fields

- `service`: `"jeedom"`
- `apikey`: Your Jeedom API key
- `jsonrpc`: JSON-RPC 2.0 method name (e.g., `"jeeObject::full"`, `"event::changes"`)
- `params`: (Optional) Additional method parameters (merged with apikey in the JSON-RPC params)
- `endpoint`: (Optional) API endpoint path, defaults to `/core/api/jeeApi.php`
- `timestamp`: Current Unix timestamp

**Note**: The gateway automatically constructs a proper JSON-RPC 2.0 payload:
```json
{
    "jsonrpc": "2.0",
    "method": "your-method",
    "params": {
        "apikey": "your-api-key",
        ...additional params
    }
}
```

#### MQTT Publish Request Fields

- `service`: `"mqtt"`
- `topic`: MQTT topic to publish to
- `message`: Message payload
- `broker_host`: (Optional) MQTT broker hostname
- `broker_port`: (Optional) MQTT broker port
- `username`: (Optional) MQTT username
- `password`: (Optional) MQTT password
- `qos`: (Optional) Quality of Service (0-2)
- `retain`: (Optional) Retain flag
- `timestamp`: Current Unix timestamp

#### MQTT Subscribe (SSE) Request Fields

Used with the `/mqtt/subscribe` endpoint for real-time subscriptions:

- `topic`: MQTT topic to subscribe to (supports wildcards: `+` for single level, `#` for multi-level)
- `broker_host`: (Optional) MQTT broker hostname
- `broker_port`: (Optional) MQTT broker port
- `username`: (Optional) MQTT username
- `password`: (Optional) MQTT password
- `qos`: (Optional) Quality of Service (0-2)
- `timestamp`: Current Unix timestamp

**Example Subscribe Payload:**
```json
{
    "topic": "home/sensors/#",
    "broker_host": "192.168.1.91",
    "broker_port": 1883,
    "qos": 1,
    "timestamp": 1234567890
}
```

**SSE Response Messages:**

Each SSE event contains an encrypted payload with one of these message types:

1. **Connected Event:**
```json
{
    "type": "connected",
    "topic": "home/sensors/#",
    "message": "Successfully connected and subscribed to home/sensors/#"
}
```

2. **Message Event:**
```json
{
    "type": "message",
    "topic": "home/sensors/temperature",
    "payload": "22.5",
    "qos": 1,
    "retain": false,
    "timestamp": 1234567890
}
```

3. **Error Event:**
```json
{
    "type": "error",
    "message": "Connection failed with code 5",
    "timestamp": 1234567890
}
```

4. **Disconnected Event:**
```json
{
    "type": "disconnected",
    "message": "Disconnected from broker (code 0)",
    "timestamp": 1234567890
}
```

All messages are encrypted using AES-GCM and base64-encoded before being sent via SSE.

### Response Format

All responses are encrypted and contain:

```json
{
    "status": 200,
    "body": "...",
    "timestamp": 1234567890
}
```

## Testing

The project includes comprehensive test suites:

### Run All Tests

```bash
python test_client/client_all_services_test.py
```

### Run Individual Tests

```bash
# Jeedom tests (7 test cases)
python test_client/client_jeedom_test.py

# MQTT tests (4 test cases)
python test_client/client_mqtt_test.py
```

### Test Coverage

**Jeedom Tests:**
- Valid timestamp requests
- Expired timestamp rejection
- Future timestamp rejection
- Parameterized requests
- Wrong secret key handling
- Missing required fields
- Multiple rapid requests (stress test)

**MQTT Tests:**
- Basic message publishing
- QoS and retain flags
- Custom broker configuration
- Error handling for missing fields

## Tailscale Funnel Deployment

Expose your gateway securely over the internet using Tailscale Funnel:

1. Install and authenticate Tailscale on your machine
2. Enable Funnel for your account
3. Start the server
4. Run the Tailscale script:

```bash
chmod +x run_tailscale.sh
./run_tailscale.sh
```

Your gateway will be accessible via a public HTTPS URL like `https://yourdevice.tail497f.ts.net`.

## Security Features

### Encryption

- **Algorithm**: AES-GCM with 256-bit keys
- **Nonce**: 12-byte random nonce per message
- **Authentication**: Built-in authenticated encryption prevents tampering
- **Key Management**: Automatic secure key generation using OS-level randomness

### Replay Attack Protection

The gateway validates timestamps to prevent replay attacks:
- Requests older than `MAX_AGE_SECONDS` are rejected
- Future timestamps are also rejected
- Default window: 60 seconds (configurable)

### Best Practices

1. **Store the secret key securely**: Never commit it to version control
2. **Use HTTPS**: Deploy with Tailscale Funnel or behind a reverse proxy with TLS
3. **Rotate keys periodically**: Generate new keys and update clients
4. **Monitor logs**: Watch for suspicious activity or repeated failed decryption attempts
5. **Network isolation**: Run the gateway in a separate network segment if possible

## Project Structure

```
FullEndToEndEncryption/
├── server/
│   ├── __init__.py
│   ├── __main__.py          # Entry point
│   ├── app.py               # Flask application factory
│   ├── config.py            # Configuration management
│   ├── crypto.py            # AES-GCM encryption/decryption
│   ├── gateway.py           # Request routing and handling
│   ├── key_manager.py       # Secret key generation
│   └── services/
│       ├── jeedom_service.py      # Jeedom JSON-RPC handler
│       ├── mqtt_service.py        # MQTT publish handler
│       └── mqtt_sse_service.py    # MQTT subscribe via SSE handler
├── test_client/
│   ├── client_jeedom_test.py      # Jeedom client and tests
│   ├── client_mqtt_test.py        # MQTT publish client and tests
│   ├── client_mqtt_sse_test.py    # MQTT SSE subscribe client
│   └── client_all_services_test.py  # Test runner
├── docker-compose.yml       # Docker Compose configuration
├── Dockerfile               # Container image definition
├── requirements.txt         # Python dependencies
├── run_tailscale.sh        # Tailscale Funnel helper script
└── README.md
```

## API Endpoints

### POST /gateway

Main gateway endpoint for all encrypted requests (Jeedom and MQTT publish).

- **Content-Type**: `application/octet-stream`
- **Body**: Base64-encoded encrypted payload
- **Response**: Base64-encoded encrypted response

### POST /mqtt/publish

Encrypted MQTT publish endpoint (via `/gateway` with `service: "mqtt"`).

- **Content-Type**: `application/octet-stream`
- **Body**: Base64-encoded encrypted payload with MQTT publish details
- **Response**: Base64-encoded encrypted response

**Payload Fields:**
- `service`: Must be `"mqtt"`
- `topic`: MQTT topic to publish to
- `message`: Message payload to publish
- `qos`: (Optional) Quality of Service (0-2), defaults to 0
- `retain`: (Optional) Retain flag, defaults to false
- `broker_host`: (Optional) MQTT broker hostname
- `broker_port`: (Optional) MQTT broker port
- `username`: (Optional) MQTT username
- `password`: (Optional) MQTT password
- `timestamp`: Current Unix timestamp

**Usage:**
This endpoint allows you to publish messages to MQTT topics through the encrypted gateway. Messages are published once and the response confirms success or failure.

### POST /mqtt/subscribe

Server-Sent Events endpoint for subscribing to MQTT topics in real-time.

- **Content-Type**: `application/octet-stream`
- **Body**: Base64-encoded encrypted payload with subscription details
- **Response**: `text/event-stream` with encrypted SSE messages
- **Headers**:
  - `Cache-Control: no-cache`
  - `X-Accel-Buffering: no`
  - `Connection: keep-alive`

**Usage:**
This endpoint establishes a persistent HTTP connection and streams MQTT messages as they arrive. Each SSE event contains an encrypted message that must be decrypted by the client. The stream remains open until:
- An error occurs
- The MQTT connection is lost
- The client closes the connection

### GET /health

Health check endpoint.

- **Response**: `{"status": "ok", "version": "1.0.0"}`

## Dependencies

### Server Dependencies

- **Flask 3.0.0**: Web framework
- **cryptography 41.0.7**: AES-GCM encryption
- **requests 2.31.0**: HTTP client for Jeedom
- **paho-mqtt 1.6.1**: MQTT client library
- **python-dotenv 1.0.0**: Environment variable management

### Client Dependencies

- **sseclient-py 1.8.0**: SSE client support (for MQTT subscriptions)

## Development

### Running in Development Mode

```bash
# Activate virtual environment
source .venv/bin/activate

# Run with auto-reload
FLASK_ENV=development python -m server
```

### Building Docker Image

```bash
docker build -t encryption-gateway:latest .
```

### Code Organization

- **Modular Design**: Separate services for different protocols
- **Type Hints**: Full type annotations for better IDE support
- **Error Handling**: Comprehensive exception handling and logging
- **Clean Architecture**: Clear separation of concerns

## Troubleshooting

### Connection Refused

Ensure the server is running and accessible:
```bash
curl http://localhost:10000/health
```

### Decryption Failed

- Verify the secret key matches between client and server
- Check that the key file hasn't been corrupted
- Ensure timestamp is within the valid window

### MQTT Connection Failed

- Verify MQTT broker is running and accessible
- Check broker hostname and port configuration
- Validate MQTT credentials if authentication is enabled

### Docker Volume Permissions

If you encounter permission issues with the data volume:
```bash
sudo chown -R 1000:1000 ./data
```

## License

This project is provided as-is for use in securing smart home and IoT communications.

## Contributing

Contributions are welcome! Areas for improvement:

- Additional service handlers (Home Assistant, InfluxDB, etc.)
- Key rotation mechanism
- Multi-user support with per-user keys
- Rate limiting and DDoS protection
- Prometheus metrics endpoint
- Android SSE client implementation example

## Acknowledgments

Built with:
- Flask for the web framework
- Cryptography library for robust encryption
- Paho MQTT for MQTT support
- Docker for containerization

## Support

For issues, questions, or contributions, please open an issue on the project repository.
