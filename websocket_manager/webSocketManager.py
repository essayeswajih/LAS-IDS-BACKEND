from fastapi import WebSocket
from fastapi.websockets import WebSocketState
import logging

class WebSocketManager:
    def __init__(self):
        self.active_connections: dict[str, list[WebSocket]] = {}
        logging.basicConfig(level=logging.INFO)

    async def connect(self, websocket: WebSocket, room_name: str):
        """Connect a WebSocket to a room"""
        if room_name not in self.active_connections:
            self.active_connections[room_name] = []
        
        self.active_connections[room_name].append(websocket)
        logging.info(f"✅ New WebSocket connection to room {room_name} (Total: {len(self.active_connections[room_name])})")

    async def disconnect(self, websocket: WebSocket):
        """Disconnect a WebSocket from the active connections"""
        for room, connections in self.active_connections.items():
            if websocket in connections:
                connections.remove(websocket)
                logging.info(f"🔌 WebSocket disconnected from room {room} (Remaining: {len(connections)})")
                
                if not connections:  # If the room is empty, delete the room
                    del self.active_connections[room]
                return

    async def send_message(self, message: str, room_name: str):
        """Send a message to all WebSocket connections in the room"""
        if room_name in self.active_connections:
            for connection in self.active_connections[room_name]:
                if connection.client_state == WebSocketState.CONNECTED:
                    try:
                        await connection.send_text(message)
                    except Exception as e:
                        logging.error(f"Error sending message to WebSocket in room {room_name}: {e}")
                        self.disconnect(connection)  # Disconnect if there's an error

    async def send_personal_message(self, user_id: str, message: dict):
        """Send a personal message to a specific user (using user_id)"""
        if user_id in self.active_connections:
            to_remove = []
            for connection in self.active_connections[user_id]:
                try:
                    if connection.client_state == WebSocketState.CONNECTED:  # Ensure the connection is still open
                        await connection.send_json(message)
                    else:
                        to_remove.append(connection)
                except Exception as e:
                    logging.error(f"Error sending message to user {user_id}: {e}")
                    to_remove.append(connection)

            for conn in to_remove:
                self.disconnect(conn)
        else:
            logging.warning(f"No active connections for user {user_id}.")

