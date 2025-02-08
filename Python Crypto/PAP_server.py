import asyncio
import websockets

async def check_pass(recieved_password):
    stored_password = "letmein"

    if recieved_password == stored_password:
        return True
    else:
        return False

async def server(websocket, path):
    access_granted_message = "Access granted!"
    access_denied_message = "Access denied!"
    hello_message = "Hello! Please provide me your password."
    await websocket.send(hello_message)

    recieved_password = await websocket.recv()
    print(f"Got new auth attempt '{recieved_password}'")

    if await check_pass(recieved_password):
        await websocket.send(access_granted_message)
        print(access_granted_message)
    else:
        await websocket.send(access_denied_message)
        print(access_denied_message)

print("Starting server...")

start_server = websockets.serve(server, "localhost", 1234)

asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()