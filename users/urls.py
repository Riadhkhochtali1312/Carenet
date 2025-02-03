from django.urls import path
from django.urls import re_path
from . import views
from .consumers import heart_consumers
from users.routing import websocket_urlpatterns
from channels.routing import ProtocolTypeRouter, URLRouter
from django.conf.urls.static import static
from django.conf import settings



application = ProtocolTypeRouter({
    "websocket": URLRouter(websocket_urlpatterns),
    # Add other protocol routers here
})


urlpatterns = [
    
    path('login/', views.log_in, name='login'),
    path('logout/<int:id>', views.log_out, name='logout'),
    path('uploaddiploma/<int:idd>',views.upload_diploma),
    path('getdiplomapicture/<int:doctor_id>',views.get_diploma_file),
    path("checkdoctorapproval/<int:doctor_id>/", views.check_doctor_approval, name="check_doctor_approval"),
    path('doctor-requests/', views.get_doctor_requests, name='doctor-requests'),
    path('countrequest',views.count_requests),
    path('approve-doctor/<int:doctor_id>/', views.approve_doctor, name='approve-doctor'),
    path('disapprove-doctor/<int:doctor_id>/', views.disapprove_doctor, name='disapprove-doctor'),
    path('validate_password/', views.validate_password),

    path('signup/', views.sign_up, name='signup'),
    path('reset/',views.reset_password,name='reset'),
    path('allusers',views.get_users,name="users"),
    path('heart',views.update_heart_rate),
    path('blood',views.update_blood_pressure),
    path('fbs',views.update_fbs),
    path('cholesterol',views.update_cholesterol),
    path('numberconnect',views.number_connect),
    path('updatedetails/<int:idd>',views.updatedetails),
    path("getdetails/<int:user_id>", views.get_details, name="get_details"),

    path('increment',views.increment),
    path('patient_list',views.patient_list),
    path('doctor_list',views.doctor_list),
    path('patient_list',views.patient_list),
    path('deleteuser/<int:iduser>',views.deleteuser),
    path('checksuperuser/<int:idd>',views.checksuperuser),
    path('treatment/<int:iddoctor>/<int:idpatient>',views.addpatient),
    path('checkifdoctor/<int:idd>',views.checkifdoctor),
    path('checkiftreatment/<int:iddoctor>/<int:idpatient>',views.checkiftreatment),
    path('search/', views.search, name='search'),
    path('mypatients/<int:iddoctor>',views.getmypatients),
    path('mydoctors/<int:idpatient>',views.getmydoctors),
    path('deletemypatient/<int:iddoctor>/<int:idpatient>',views.deletemypatient),
    path('heartratelist/<int:idpatient>',views.heart_rate_list),
    path('bloodpressurelist/<int:idpatient>',views.blood_pressure_list),
    path('fbslist/<int:idpatient>',views.fbs_list),
    path('cholesterollist/<int:idpatient>',views.cholesterol_list),

    path('message/<int:idsender>/<int:idreciever>',views.send_message),
    path('getmessages/<int:idsender>/<int:idreciever>/', views.get_messages),
    path('addnotif/<int:idpatient>',views.add_notification),
    path('getnotifs/<int:idpatient>',views.get_notifications),


    path('predict/<int:age>/<int:sex>/<int:heart_rate>/<int:fbs>/<int:chol>',views.predict_view),
    path('getvitals/<int:idpatient>',views.getvitals),
    path('add_appointment/<int:iddoctor>/<int:idpatient>', views.add_appointment),
    path('get_appointments/<int:iddoctor>/', views.get_appointments),
    path('get_appointments_patient/<int:idpatient>/', views.get_appointments_patient),

    path('delete_appointment/<int:iddoctor>/<int:idapp>', views.deleteappointment),
    path('updateprofilepicture/<int:idd>', views.update_profile_picture, name='update_profile_picture'),
    path('profile_picture/<int:user_id>', views.get_profile_picture, name='get_profile_picture'),
    re_path(r'^verify_email/(?P<email_b64>[^/]+)/(?P<token>[^/]+)/$', views.verify_email, name='verify_email'),





 

 

]+websocket_urlpatterns+static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)


