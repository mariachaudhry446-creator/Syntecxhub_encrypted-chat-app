"""
Encrypted Chat Server
Handles multiple clients, relays encrypted messages, and logs all traffic
"""
import socket
import threading
import logging
from datetime import datetime
from typing import Dict, Set
import json

class ChatServer:
    def __init__(self, host='localhost', port=5555):
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients: Dict[socket.socket, str] = {}  # socket -> username
        self.usernames: Dict[str, socket.socket] = {}  # username -> socket
        self.lock = threading.Lock()
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('chat.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def start(self):
        """Start the chat server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        
        self.logger.info(f"Server started on {self.host}:{self.port}")
        
        try:
            while True:
                client_socket, address = self.server_socket.accept()
                self.logger.info(f"New connection from {address}")
                
                # Handle client in separate thread
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address)
                )
                client_thread.daemon = True
                client_thread.start()
        except KeyboardInterrupt:
            self.logger.info("Server shutting down...")
        finally:
            self.stop()
    
    def handle_client(self, client_socket: socket.socket, address):
        """Handle individual client connection"""
        try:
            # Receive username
            username_data = client_socket.recv(1024).decode('utf-8')
            username = json.loads(username_data)['username']
            
            # Register client
            with self.lock:
                if username in self.usernames:
                    client_socket.send(json.dumps({'error': 'Username already taken'}).encode())
                    client_socket.close()
                    return
                
                self.clients[client_socket] = username
                self.usernames[username] = client_socket
            
            # Send welcome message
            welcome_msg = f"Welcome {username}! You have joined the encrypted chat."
            client_socket.send(json.dumps({'type': 'system', 'message': welcome_msg}).encode())
            
            # Broadcast join message
            self.broadcast_system_message(f"{username} has joined the chat", exclude=client_socket)
            
            self.logger.info(f"User {username} registered from {address}")
            
            # Handle incoming messages
            while True:
                encrypted_data = client_socket.recv(4096).decode('utf-8')
                if not encrypted_data:
                    break
                
                # Parse message
                try:
                    message_data = json.loads(encrypted_data)
                    msg_type = message_data.get('type', 'chat')
                    
                    if msg_type == 'chat':
                        # Log encrypted message
                        self.log_message(username, message_data['encrypted_message'])
                        
                        # Forward to recipient or broadcast
                        target = message_data.get('target')
                        if target and target != 'all':
                            self.send_private_message(username, target, message_data['encrypted_message'])
                        else:
                            self.broadcast_message(username, message_data['encrypted_message'], exclude=client_socket)
                    elif msg_type == 'private':
                        target = message_data['target']
                        self.send_private_message(username, target, message_data['encrypted_message'])
                        
                except json.JSONDecodeError:
                    self.logger.error(f"Invalid message format from {username}")
                    
        except (ConnectionResetError, BrokenPipeError, OSError):
            self.logger.info(f"Client {address} disconnected")
        finally:
            self.remove_client(client_socket)
    
    def broadcast_message(self, sender: str, encrypted_msg: str, exclude=None):
        """Broadcast message to all clients"""
        message_data = json.dumps({
            'type': 'chat',
            'sender': sender,
            'encrypted_message': encrypted_msg,
            'timestamp': datetime.now().isoformat()
        })
        
        with self.lock:
            for client in list(self.clients.keys()):
                if client != exclude:
                    try:
                        client.send(message_data.encode('utf-8'))
                    except (BrokenPipeError, OSError):
                        pass
    
    def broadcast_system_message(self, message: str, exclude=None):
        """Broadcast system message (plaintext)"""
        message_data = json.dumps({
            'type': 'system',
            'message': message,
            'timestamp': datetime.now().isoformat()
        })
        
        with self.lock:
            for client in list(self.clients.keys()):
                if client != exclude:
                    try:
                        client.send(message_data.encode('utf-8'))
                    except (BrokenPipeError, OSError):
                        pass
    
    def send_private_message(self, sender: str, target: str, encrypted_msg: str):
        """Send private message to specific user"""
        with self.lock:
            if target in self.usernames:
                target_socket = self.usernames[target]
                message_data = json.dumps({
                    'type': 'private',
                    'sender': sender,
                    'encrypted_message': encrypted_msg,
                    'timestamp': datetime.now().isoformat()
                })
                try:
                    target_socket.send(message_data.encode('utf-8'))
                    
                    # Also send confirmation to sender
                    sender_socket = self.usernames.get(sender)
                    if sender_socket:
                        confirm_data = json.dumps({
                            'type': 'system',
                            'message': f"[Private to {target}] Message sent"
                        })
                        sender_socket.send(confirm_data.encode('utf-8'))
                except (BrokenPipeError, OSError):
                    self.logger.error(f"Failed to send private message to {target}")
            else:
                # Notify sender that user doesn't exist
                sender_socket = self.usernames.get(sender)
                if sender_socket:
                    error_data = json.dumps({
                        'type': 'error',
                        'message': f"User {target} not found"
                    })
                    sender_socket.send(error_data.encode('utf-8'))
    
    def log_message(self, sender: str, encrypted_msg: str):
        """Log encrypted message to file"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'sender': sender,
            'encrypted_message': encrypted_msg
        }
        self.logger.info(f"Message from {sender}: {encrypted_msg[:50]}...")
        
        # Also save to a separate encrypted log
        with open('message_log.json', 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    
    def remove_client(self, client_socket: socket.socket):
        """Remove client from server"""
        with self.lock:
            if client_socket in self.clients:
                username = self.clients[client_socket]
                del self.clients[client_socket]
                if username in self.usernames:
                    del self.usernames[username]
                
                self.logger.info(f"User {username} disconnected")
                self.broadcast_system_message(f"{username} has left the chat")
            
            try:
                client_socket.close()
            except:
                pass
    
    def stop(self):
        """Stop the server and clean up"""
        if self.server_socket:
            self.server_socket.close()
        
        # Close all client connections
        with self.lock:
            for client in list(self.clients.keys()):
                try:
                    client.close()
                except:
                    pass
            self.clients.clear()
            self.usernames.clear()

def main():
    import sys
    
    host = input("Enter server host (default: localhost): ") or 'localhost'
    port = input("Enter server port (default: 5555): ")
    port = int(port) if port else 5555
    
    server = ChatServer(host, port)
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.stop()

if __name__ == "__main__":
    main()