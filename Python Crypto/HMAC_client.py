#!/usr/bin/env python
# PAP client
import asyncio
import websockets
import hashlib

def gen_sha256_hmac(message, key):
    blocksize = 64

    trans_5C = bytes((x ^ 0x5C) for x in range(256))
    trans_36 = bytes((x ^ 0x36) for x in range(256))

    key_hex = key.encode().hex()[2:]
    key_bytes = bytes.fromhex(key_hex).ljust(blocksize, b'\0')

    xored_key_bytes_ipad = key_bytes.translate(trans_36)
    h1 = hashlib.sha256(xored_key_bytes_ipad + message.encode())

    xored_key_bytes_opad = key_bytes.translate(trans_5C)
    return hashlib.sha256(xored_key_bytes_opad + h1.digest()).hexdigest()

async def try_auth(uri):
    async with websockets.connect(uri) as websocket:
        shared_key = "supersecret"
        message = f"Hello from {input("write ur name")}"

        welcome_message = await websocket.recv()
        print(f"Server answered: {welcome_message}")

        message_HMAC = gen_sha256_hmac(message, shared_key)
        print(f"I send message '{message}' with HMAC '{message_HMAC}'")
        await websocket.send(f"{message},{message_HMAC}")

        answer = await websocket.recv()
        print(answer)

asyncio.get_event_loop().run_until_complete(
    try_auth('ws://localhost:1234')
)
