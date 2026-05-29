# 🔐 Encrypted Chat Application

A secure real-time chat application with **AES-256-GCM encryption** for all messages.

## Features
- End-to-end encryption using AES-256-GCM
- Multi-client support with concurrent connections
- Public and private messaging
- Server-side encrypted message logging
- Unique IV per message for enhanced security

- ## Tech Stack
- Python 3.7+
- Cryptography library (AES-GCM)
- Socket programming (TCP)
- Multi-threading

## Usage
1. Generate Encryption Key
       python key_manager.py
2. Start Server
       python server.py
3. Connect Clients
       python client.py

## Commands
@username message - Send private message

/quit - Exit chat

/help - Show help
