import requests
import base64
import json
import time
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv


class EncryptedClient:
    def __init__(self, gateway_url: str, secret_key: str, jeedom_apikey: str):
        """
        Initialize encrypted client.
        
        Args:
            gateway_url: URL of the gateway server (e.g., "http://localhost:8081")
            secret_key: 64-character hex string (32 bytes)
            jeedom_apikey: API key for Jeedom
        """
        self.gateway_url = gateway_url
        self.secret_key = bytes.fromhex(secret_key)
        self.jeedom_apikey = jeedom_apikey
    
    def encrypt(self, data: dict) -> bytes:
        """Encrypt data using AES-GCM."""
        nonce = os.urandom(12)
        aesgcm = AESGCM(self.secret_key)
        plaintext = json.dumps(data).encode()
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext
    
    def decrypt(self, data: bytes) -> dict:
        """Decrypt data using AES-GCM."""
        nonce, ciphertext = data[:12], data[12:]
        aesgcm = AESGCM(self.secret_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(plaintext)
    
    def send_request(self, jsonrpc: str, params: dict = None, service: str = "jeedom") -> dict:
        """
        Send encrypted JSON-RPC request to Jeedom via gateway server.
        
        Args:
            jsonrpc: JSON-RPC method (e.g., "event::changes")
            params: Optional parameters for the JSON-RPC call
            service: Service type ("jeedom" or "mqtt")
            
        Returns:
            Decrypted response as dict with keys: status, body, timestamp
        """
        # Prepare request payload
        payload = {
            "service": service,
            "endpoint": "/core/api/jeeApi.php",
            "apikey": self.jeedom_apikey,
            "jsonrpc": jsonrpc,
            "timestamp": int(time.time())
        }
        
        if params:
            payload["params"] = params
        
        # Encrypt and encode
        encrypted_data = self.encrypt(payload)
        encoded_data = base64.b64encode(encrypted_data)
        
        # Send to gateway
        response = requests.post(
            f"{self.gateway_url}/gateway",
            data=encoded_data,
            headers={"Content-Type": "application/octet-stream"},
            timeout=30
        )
        
        # Decrypt response
        encrypted_response = base64.b64decode(response.content)
        decrypted_response = self.decrypt(encrypted_response)
        
        return decrypted_response
    
    def send_mqtt(self, topic: str, message: str, broker_host: str = None, 
                  broker_port: int = None, username: str = None, 
                  password: str = None, qos: int = 0, retain: bool = False) -> dict:
        """
        Send encrypted MQTT publish request via gateway server.
        
        Args:
            topic: MQTT topic to publish to
            message: Message payload to publish
            broker_host: MQTT broker host (optional, uses server default)
            broker_port: MQTT broker port (optional, uses server default)
            username: MQTT username (optional)
            password: MQTT password (optional)
            qos: Quality of Service level (0, 1, or 2)
            retain: Whether to retain the message
            
        Returns:
            Decrypted response as dict with keys: status, body, timestamp
        """
        # Prepare MQTT payload
        payload = {
            "service": "mqtt",
            "topic": topic,
            "message": message,
            "qos": qos,
            "retain": retain,
            "timestamp": int(time.time())
        }
        
        # Add optional parameters
        if broker_host:
            payload["broker_host"] = broker_host
        if broker_port:
            payload["broker_port"] = broker_port
        if username:
            payload["username"] = username
        if password:
            payload["password"] = password
        
        # Encrypt and encode
        encrypted_data = self.encrypt(payload)
        encoded_data = base64.b64encode(encrypted_data)
        
        # Send to gateway
        response = requests.post(
            f"{self.gateway_url}/gateway",
            data=encoded_data,
            headers={"Content-Type": "application/octet-stream"},
            timeout=30
        )
        
        # Decrypt response
        encrypted_response = base64.b64decode(response.content)
        decrypted_response = self.decrypt(encrypted_response)
        
        return decrypted_response


def main():
    """Example usage of the encrypted client."""

    # Load environment variables from .env file
    load_dotenv()

    # Load secret key from file
    secret_key_file = "server/secret_key.txt"
    try:
        with open(secret_key_file, 'r', encoding='utf-8') as f:
            SECRET_KEY = f.read().strip()
        print(f"Loaded secret key from {secret_key_file}")
    except FileNotFoundError:
        print(f"Error: {secret_key_file} not found!")
        print("Please run the server first to generate the secret key.")
        return
    except Exception as e:
        print(f"Error reading secret key: {e}")
        return
    
    # Configuration
    GATEWAY_URL = "http://localhost:10000"
    
    # Create client
    client = EncryptedClient(GATEWAY_URL, SECRET_KEY, os.getenv("JEEDOM_APIKEY", ""))
    
    total_tests = 0
    passed_tests = 0
    failed_tests = 0
    
    try:
        # Test 1: Valid timestamp with datetime method
        total_tests += 1
        print("Test 1: Valid timestamp request (datetime method)")
        try:
            response = client.send_request(jsonrpc="datetime")
            print(f"Status: {response['status']}")
            print(f"Response body: {response['body']}")
            print(f"Timestamp: {response['timestamp']}")

            # Check if response is valid JSON-RPC 2.0
            if response['status'] == 200:
                body = response['body']
                if isinstance(body, dict) and body.get('jsonrpc') == '2.0' and 'result' in body:
                    print(f"✓ Test 1 PASSED - Got datetime: {body['result']}\n")
                    passed_tests += 1
                else:
                    print(f"✗ Test 1 FAILED - Invalid JSON-RPC response format\n")
                    failed_tests += 1
            else:
                print("✗ Test 1 FAILED\n")
                failed_tests += 1
        except Exception as e:
            print(f"✗ Test 1 FAILED: {e}\n")
            failed_tests += 1
        
        # Test 2: Expired timestamp (should be rejected)
        total_tests += 1
        print("Test 2: Expired timestamp request (70 seconds old)")
        try:
            payload = {
                "service": "jeedom",
                "apikey": client.jeedom_apikey,
                "jsonrpc": "datetime",
                "timestamp": int(time.time()) - 70  # 70 seconds ago
            }
            encrypted_data = client.encrypt(payload)
            encoded_data = base64.b64encode(encrypted_data)
            
            response = requests.post(
                f"{client.gateway_url}/gateway",
                data=encoded_data,
                headers={"Content-Type": "application/octet-stream"},
                timeout=30
            )
            
            encrypted_response = base64.b64decode(response.content)
            decrypted_response = client.decrypt(encrypted_response)
            print(f"Status: {decrypted_response['status']}")
            body = decrypted_response['body'][:200] + '...' if len(decrypted_response['body']) > 200 else decrypted_response['body']
            print(f"Response: {body}")
            print(f"Timestamp: {decrypted_response['timestamp']}")
            if decrypted_response['status'] == 403 and 'expired' in decrypted_response['body'].lower():
                print("✓ Test 2 PASSED (correctly rejected)\n")
                passed_tests += 1
            else:
                print("✗ Test 2 FAILED (should have been rejected)\n")
                failed_tests += 1
        except Exception as e:
            print(f"✗ Test 2 FAILED: {e}\n")
            failed_tests += 1
        
        # Test 3: Request with jeeObject::full method
        total_tests += 1
        print("Test 3: Request with jeeObject::full method")
        try:
            response = client.send_request(jsonrpc="jeeObject::full")
            print(f"Status: {response['status']}")
            body = response['body']

            # For large responses, show summary
            if isinstance(body, dict):
                print(f"Response type: JSON-RPC 2.0 response")
                if 'result' in body:
                    result = body['result']
                    if isinstance(result, list):
                        print(f"Result: List with {len(result)} items")
                    elif isinstance(result, dict):
                        print(f"Result: Dict with keys: {list(result.keys())[:5]}")
                    else:
                        print(f"Result: {result}")
                print(f"✓ Test 3 PASSED\n")
                passed_tests += 1
            else:
                print(f"Response: {str(body)[:200]}")
                print("✗ Test 3 FAILED - Expected JSON response\n")
                failed_tests += 1
        except Exception as e:
            print(f"✗ Test 3 FAILED: {e}\n")
            failed_tests += 1
        
        # Test 4: Future timestamp (should be rejected)
        total_tests += 1
        print("Test 4: Future timestamp request (70 seconds ahead)")
        try:
            payload = {
                "service": "jeedom",
                "apikey": client.jeedom_apikey,
                "jsonrpc": "datetime",
                "timestamp": int(time.time()) + 70  # 70 seconds in future
            }
            encrypted_data = client.encrypt(payload)
            encoded_data = base64.b64encode(encrypted_data)
            
            response = requests.post(
                f"{client.gateway_url}/gateway",
                data=encoded_data,
                headers={"Content-Type": "application/octet-stream"},
                timeout=30
            )
            
            encrypted_response = base64.b64decode(response.content)
            decrypted_response = client.decrypt(encrypted_response)
            print(f"Status: {decrypted_response['status']}")
            body = decrypted_response['body'][:200] + '...' if len(decrypted_response['body']) > 200 else decrypted_response['body']
            print(f"Response: {body}")
            print(f"Timestamp: {decrypted_response['timestamp']}")
            if decrypted_response['status'] == 403 and 'expired' in decrypted_response['body'].lower():
                print("✓ Test 4 PASSED (correctly rejected)\n")
                passed_tests += 1
            else:
                print("✗ Test 4 FAILED (should have been rejected)\n")
                failed_tests += 1
        except Exception as e:
            print(f"✗ Test 4 FAILED: {e}\n")
            failed_tests += 1
        
        # Test 5: Wrong secret key (should fail to decrypt)
        total_tests += 1
        print("Test 5: Wrong secret key (should fail decryption)")
        try:
            wrong_client = EncryptedClient(
                GATEWAY_URL,
                "0000000000000000000000000000000000000000000000000000000000000000",
                JEEDOM_APIKEY
            )
            response = wrong_client.send_request(jsonrpc="event::changes")
            print("✗ Test 5 FAILED (should have failed decryption)\n")
            failed_tests += 1
        except Exception as e:
            print(f"Expected error: {str(e)[:100]}")
            print("✓ Test 5 PASSED (correctly failed)\n")
            passed_tests += 1
        
        # Test 6: Missing required field (no jsonrpc)
        total_tests += 1
        print("Test 6: Missing required field (no jsonrpc)")
        try:
            payload = {
                "service": "jeedom",
                "apikey": client.jeedom_apikey,
                "timestamp": int(time.time())
            }
            encrypted_data = client.encrypt(payload)
            encoded_data = base64.b64encode(encrypted_data)
            
            response = requests.post(
                f"{client.gateway_url}/gateway",
                data=encoded_data,
                headers={"Content-Type": "application/octet-stream"},
                timeout=30
            )
            
            encrypted_response = base64.b64decode(response.content)
            decrypted_response = client.decrypt(encrypted_response)
            print(f"Status: {decrypted_response['status']}")
            body = decrypted_response['body'][:200] + '...' if len(decrypted_response['body']) > 200 else decrypted_response['body']
            print(f"Response: {body}")
            if decrypted_response['status'] == 403:
                print("✓ Test 6 PASSED (correctly rejected)\n")
                passed_tests += 1
            else:
                print("✗ Test 6 FAILED (should have been rejected)\n")
                failed_tests += 1
        except Exception as e:
            print(f"Expected error: {str(e)[:100]}")
            print("✓ Test 6 PASSED (correctly failed)\n")
            passed_tests += 1
        
        # Test 7: Multiple rapid requests (stress test)
        total_tests += 1
        print("Test 7: Multiple rapid requests (5 requests)")
        try:
            success_count = 0
            for i in range(5):
                response = client.send_request(jsonrpc="datetime")
                if response['status'] == 200:
                    success_count += 1
            print(f"Successfully completed {success_count}/5 requests")
            if success_count == 5:
                print("✓ Test 7 PASSED\n")
                passed_tests += 1
            else:
                print("✗ Test 7 FAILED\n")
                failed_tests += 1
        except Exception as e:
            print(f"✗ Test 7 FAILED: {e}\n")
            failed_tests += 1
        
    except Exception as e:
        print(f"Critical Error: {e}")
    
    # Print summary
    print("=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"Total tests run: {total_tests}")
    print(f"Tests passed:    {passed_tests} ✓")
    print(f"Tests failed:    {failed_tests} ✗")
    print(f"Success rate:    {(passed_tests/total_tests*100):.1f}%" if total_tests > 0 else "N/A")
    print("=" * 60)


if __name__ == "__main__":
    main()
