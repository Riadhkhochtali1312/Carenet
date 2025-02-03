from django.urls import re_path
from channels.routing import URLRouter
from users.consumers import heart_consumers,blood_press_consum


from django.urls import path

websocket_urlpatterns = [
    re_path(r'ws/heart_rate/$', heart_consumers.HeartRateConsumer.as_asgi()),
    re_path(r'ws/blood_pressure/$',blood_press_consum.BloodPressureConsumer.as_asgi())
]