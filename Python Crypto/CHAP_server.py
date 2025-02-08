import asyncio
import websockets
import hashlib
import random
import string

async def check_pass(recieved_password, challenge):
    stored_password = "letmein".encode()
    challenge = challenge.encode()
    calculated_hash = hashlib.sha256(stored_password + challenge).hexdigest()
    if recieved_password == calculated_hash:
        return True
    else:
        return False


async def server(websocket, path):
    chall_len = 5 
    access_granted_message = "Access granted!"
    access_denied_message = "Access denied!"
    challenge_letters = [random.choice(string.ascii_letters) for _ in range(chall_len)]
    challenge = "".join(challenge_letters)

    hello_message = f"Hello! Please provide me a sha256(password + {challenge})"
    await websocket.send(hello_message)

    recieved_hash = await websocket.recv()
    print(f"Got new auth attempt '{recieved_hash}'")

    if await check_pass(recieved_hash, challenge):
        await websocket.send(access_granted_message)
        print(access_granted_message)
    else:
        await websocket.send(access_denied_message)
        print(access_denied_message)

print("Starting server...")
start_server = websockets.serve(server, "localhost", 1234)

asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()