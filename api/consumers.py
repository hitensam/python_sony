import re
import json
from channels.generic.websocket import AsyncWebsocketConsumer


class LoginSignUpConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        query_string = self.scope.get('query_string', b'').decode('utf-8')
        params = dict(param.split('=') for param in query_string.split('&') if '=' in param)

        group_name = re.sub(r'[^a-zA-Z0-9.-]', '-', params.get('email'))

        self.room_name = group_name
        self.room_group_name = group_name

        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        await self.accept()

    async def disconnect(self, close_code):
        pass

    async def task_data(self, msg):
        data = msg['data']
        # Send message to WebSocket
        await self.send(text_data=json.dumps({'data': data}))
