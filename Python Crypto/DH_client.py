from math import gcd as bltin_gcd
import random
import Crypto.Util.number
import asyncio
import websockets

def primRoots(info):
    #Функция подсчета первообразного корня по модулю. Можно найти пример реализации в интернете
    required_set = {num for num in range(1, modulo) if bltin_gcd(num, modulo) }
    return [g for g in range(1, modulo) if required_set == {pow(g, powers, modulo) for powers in range(1, modulo)}]


def GenDHParams():
    bits = 8
    PrivKey = random.randint(1,2**bits)
    # p - случайное простое число в диапазоне 2^8
    p = Crypto.Util.number.getPrime(bits, randfunc = Crypto.Random.get_random_bytes)
    # g - первообразный корень по модулю p
    g = primRoots(p)[-1]
    Pkey = (g ** PrivKey) % p
    return PrivKey, Pkey, p, g

async def stert_DH_exchange(uri):
    async with websockets.connect(uri) as websocket:
        welcome_message = await websocket.recv()
        print(welcome_message)

        send_Pkey, PrivKey, p, g = GenDHParams()

        send_Pkey = F"{send_Pkey},{p},{g}".encode()

        print(f"Sending public key: {send_Pkey}")
        await websocket.send(send_Pkey)

        recieved_Pkey = await websocket.recv()
        print(f"Got public key: {recieved_Pkey}")

        shared_secret = int(recieved_Pkey.decode()) ** PrivKey % p
        print(f"Shared secret: {shared_secret}")

asyncio.get_event_loop().run_until_complete(
    stert_DH_exchange("ws://localhost:1234")
)