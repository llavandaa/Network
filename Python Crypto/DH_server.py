from math import gcd as bltin_gcd
import random
import Crupto.Util.number
import asyncio
import websockets

def GenDHParams(p, g):
    bits = 8
    PrivKey = random.randint(1,2**bits)
    Pkey = (g ** PrivKey) % p
    return PrivKey, Pkey

async def serve(websocket,path):
    hello_message = "Hello! Please provide me your public key."
    await websocket.send(hello_message)

    recieved_Pkey = await websocket.recv()
    Pkey, p, g = recieved_Pkey.decode().split(",")
    Pkey = int(Pkey)
    p= int(p)
    g = int(g)

    print(f"Got new auth attempt '{Pkey}', Prime number: {p}, Prime root: {g}")

    Send_Pkey, PrivKey = GenDHParams(p, g)

    print(f"Sending public key: {Send_Pkey}")

    await websocket.send(str(Send_Pkey).encode())

    shared_secret = Pkey ** PrivKey % p

    print(f"Shared secret: {shared_secret}")

    print('Starting server...')

    start_server = websockets.serve(server, "localhost", 1234)

    asyncio.get_event_loop().run_until_complete(start_server)
    asyncio.get_event_loop().run_forever()