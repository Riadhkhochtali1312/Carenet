import os

from django.core.asgi import get_asgi_application
import django

from channels.routing import ProtocolTypeRouter, URLRouter

from channels.auth import AuthMiddlewareStack
from django.urls import path
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'project.settings')
from users.routing import websocket_urlpatterns



ws_pattern = []

application = ProtocolTypeRouter({
    "http" : get_asgi_application(),
    "websocket" : AuthMiddlewareStack(URLRouter(
        websocket_urlpatterns
    ))
})