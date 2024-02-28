from fastapi import WebSocket

# Function to raise unauthorized exception
async def raise_unauthorized_exception(websocket: WebSocket):
    await websocket.close(code=1008)
