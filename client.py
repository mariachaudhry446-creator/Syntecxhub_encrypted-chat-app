"""
Encrypted Chat Client
Connects to server, encrypts/decrypts messages using AES
"""
import socket
import threading
import json
import sys
from crypto_utils import AESChatCrypto

class ChatClient:
    def __init__(self, host='localhost', port=5555, key=None, username=None):
        self.host = host
        self.port = port
        self.socket = None
        self.username = username
        self.crypto = AESChatCrypto(key) if key else None
        self.running = False
        self.receive_thread = None
        
    def connect(self):
        """Connect to the chat server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            
            # Send username
            username_data = json.dumps({'username': self.username})
            self.socket.send(username_data.encode('utf-8'))
            
            # Start receive thread
            self.running = True
            self.receive_thread = threading.Thread(target=self.receive_messages)
            self.receive_thread.daemon = True
            self.receive_thread.start()
            
            return True
        except Exception as e:
            print(f"Failed to connect: {e}")
            return False
    
    def send_message(self, plaintext: str):
        """Encrypt and send a message"""
        if not plaintext or not plaintext.strip():
            return
        
        # Check for private message format: @username message
        if plaintext.startswith('@'):
            parts = plaintext.split(' ', 1)
            if len(parts) == 2:
                target = parts[0][1:]  # Remove @
                message = parts[1]
                
                # Encrypt the message
                encrypted = self.crypto.encrypt_message(message)
                
                # Send private message
                message_data = json.dumps({
                    'type': 'private',
                    'target': target,
                    'encrypted_message': encrypted
                })
                self.socket.send(message_data.encode('utf-8'))
                return
        
        # Regular broadcast message
        encrypted = self.crypto.encrypt_message(plaintext)
        message_data = json.dumps({
            'type': 'chat',
            'encrypted_message': encrypted
        })
        self.socket.send(message_data.encode('utf-8'))
    
    def receive_messages(self):
        """Receive and decrypt messages from server"""
        while self.running:
            try:
                data = self.socket.recv(4096).decode('utf-8')
                if not data:
                    break
                
                message = json.loads(data)
                msg_type = message.get('type')
                
                if msg_type == 'system':
                    # System message (already plaintext)
                    print(f"\n[SYSTEM] {message['message']}")
                    
                elif msg_type == 'error':
                    print(f"\n[ERROR] {message['message']}")
                    
                elif msg_type == 'chat':
                    # Regular chat message - decrypt it
                    sender = message['sender']
                    encrypted = message['encrypted_message']
                    try:
                        decrypted = self.crypto.decrypt_message(encrypted)
                        print(f"\n[{sender}]: {decrypted}")
                    except Exception as e:
                        print(f"\n[ERROR] Failed to decrypt message from {sender}: {e}")
                        
                elif msg_type == 'private':
                    # Private message
                    sender = message['sender']
                    encrypted = message['encrypted_message']
                    try:
                        decrypted = self.crypto.decrypt_message(encrypted)
                        print(f"\n[PRIVATE {sender}]: {decrypted}")
                    except Exception as e:
                        print(f"\n[ERROR] Failed to decrypt private message: {e}")
                
                # Print prompt again
                print(f"\n[{self.username}]: ", end='', flush=True)
                
            except json.JSONDecodeError:
                print("\n[ERROR] Invalid message format")
            except (ConnectionResetError, BrokenPipeError):
                print("\n[ERROR] Connection to server lost")
                break
            except Exception as e:
                print(f"\n[ERROR] {e}")
                break
        
        self.running = False
    
    def run(self):
        """Main client loop"""
        if not self.connect():
            return
        
        print(f"\n=== Connected to chat server as {self.username} ===")
        print("Commands:")
        print("  @username message - Send private message")
        print("  /quit - Exit the chat")
        print("  /help - Show this help")
        print("==========================================\n")
        
        try:
            while self.running:
                message = input(f"[{self.username}]: ")
                
                if message.lower() == '/quit':
                    print("Disconnecting...")
                    break
                elif message.lower() == '/help':
                    print("\nCommands:")
                    print("  @username message - Send private message to specific user")
                    print("  /quit - Exit the chat")
                    print("  /help - Show this help\n")
                    continue
                
                self.send_message(message)
                
        except KeyboardInterrupt:
            print("\nDisconnecting...")
        finally:
            self.disconnect()
    
    def disconnect(self):
        """Disconnect from server"""
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass

def main():
    print("=== Encrypted Chat Client ===")
    
    # Get connection details
    host = input("Enter server host (default: localhost): ") or 'localhost'
    port = input("Enter server port (default: 5555): ")
    port = int(port) if port else 5555
    username = input("Enter your username: ")
    
    if not username:
        print("Username required!")
        return
    
    # Load or generate encryption key
    key_option = input("Load key from file? (y/n): ").lower()
    
    if key_option == 'y':
        key_file = input("Enter key filename (default: chat_key.key): ") or 'chat_key.key'
        try:
            key = AESChatCrypto.load_key_from_file(key_file)
            print(f"Key loaded from {key_file}")
        except FileNotFoundError:
            print(f"Key file not found! Generating new key...")
            key = AESChatCrypto.generate_and_save_key()
    else:
        key_input = input("Enter base64 key (or press Enter to generate new): ")
        if key_input:
            key = AESChatCrypto.string_to_key(key_input)
        else:
            key = AESChatCrypto.generate_and_save_key()
    
    # Create and run client
    client = ChatClient(host, port, key, username)
    client.run()

if __name__ == "__main__":
    main()