import websocket
import json
import time
import random

def on_message(ws, message):
    print(message)

def on_error(ws, error):
    print(error)

def on_close(ws,a,b):
    print("Connection closed")

def on_open(ws):
    print("Connection opened")

    # Send simulated heart rate data
    for i in range(10):
        data = {"heart_rate": random.randint(60, 100)}
        ws.send(json.dumps(data))
        time.sleep(1)

websocket.enableTrace(True)

ws = websocket.WebSocketApp(
    "ws://localhost:8001/ws/heart_rate/",
    on_message = on_message,
    on_error = on_error,
    on_close = on_close,
    on_open = on_open
)

ws.run_forever()
