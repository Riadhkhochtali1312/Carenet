from background_task import background
import pyrebase
import jwt
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import requests
import json
from django.http import HttpResponse
import re
import time
import random
import threading
from .models import User
from django.db import models
from rest_framework.response import Response
from django.contrib.auth.hashers import make_password
from rest_framework import status
from rest_framework.decorators import api_view
from django.contrib.auth import authenticate
from django.contrib.auth import logout
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db.models import Q
from datetime import datetime, timedelta
from rest_framework.decorators import api_view, permission_classes,authentication_classes
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from .models import vitalss
from django.core.mail import send_mail
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.utils.encoding import force_str
from django.contrib.auth.decorators import login_required

from django.core.mail import send_mail





import json

@permission_classes(IsAuthenticated)
@api_view(['GET'])
def number_connect(request):
     all= BlacklistToken.objects.all()
     try:
         for one in all:
              idd=one.user_id
              data=User.objects.get(id=idd)
              return JsonResponse({'message':data.number_connect})
     except:
        return JsonResponse({'message':"nobody is connected"})


def generate_heart_rate():
    return random.randint(60, 150)

def generate_blood_pressure():
        return random.randint(100, 120)

def generate_fbs():
    return random.randint(50,150)

def generate_cholesterol():
    return random.randint(150,250)


@permission_classes(IsAuthenticated)
@api_view(['POST'])
def update_heart_rate(request):
    
    while True:
     time.sleep(5)
     all= BlacklistToken.objects.all()
     for one in all:
         idd=one.user_id
         data=User.objects.get(id=idd)
         heart_rate = generate_heart_rate()
         data.heart_rate = heart_rate
         vitals = vitalss(a=heart_rate,b=generate_blood_pressure(),c=generate_fbs(),d=generate_cholesterol(),user=data)
         data.save()
         vitals.save()
         return JsonResponse({'heart_rate': heart_rate})



@permission_classes(IsAuthenticated)
@api_view(['POST'])
def update_blood_pressure(request):
    
    while True:
     time.sleep(5)
     all= BlacklistToken.objects.all()
     for one in all:
         idd=one.user_id
         data=User.objects.get(id=idd)
         blood_pressure = generate_blood_pressure()
         data.blood_pressure = blood_pressure
         data.save()
         return JsonResponse({'blood_pressure': blood_pressure})

@permission_classes(IsAuthenticated)
@api_view(['POST'])
def update_fbs(request):
    
    while True:
     time.sleep(5)
     all= BlacklistToken.objects.all()
     for one in all:
         idd=one.user_id
         data=User.objects.get(id=idd)
         fbs = generate_fbs()
         data.fbs = fbs
         data.save()
         return JsonResponse({'fbs': fbs})

@permission_classes(IsAuthenticated)
@api_view(['POST'])
def update_cholesterol(request):
    
    while True:
     time.sleep(5)
     all= BlacklistToken.objects.all()
     for one in all:
         idd=one.user_id
         data=User.objects.get(id=idd)
         cholesterol = generate_cholesterol()
         data.cholesterol = cholesterol
         data.save()
         return JsonResponse({'cholesterol': cholesterol})

    


class BlacklistToken(models.Model):
    user = models.ForeignKey('User', on_delete=models.CASCADE)
    token = models.CharField(max_length=1000)


class treatment(models.Model):
    doctor = models.ForeignKey('User', on_delete=models.CASCADE, related_name='treatments_as_doctor')
    patient = models.ForeignKey('User', on_delete=models.CASCADE, related_name='treatments_as_patient')


class message(models.Model):
    content=models.CharField(max_length=200,default='')
    sender = models.ForeignKey('User', on_delete=models.CASCADE, related_name='sender')
    reciever = models.ForeignKey('User', on_delete=models.CASCADE, related_name='reciever')

class notifications(models.Model):
    content=models.CharField(max_length=200,default='')
    patient_id=models.ForeignKey('User', on_delete=models.CASCADE, related_name='patient_id')
    time=models.DateTimeField(auto_now=True)


class appointment(models.Model):
    date=models.DateField()  
    patient=models.ForeignKey('User', on_delete=models.CASCADE, related_name='patient')
    doctor=models.ForeignKey('User', on_delete=models.CASCADE, related_name='doctor')

class Doctors(models.Model):
        doctor_id=models.ForeignKey('User', on_delete=models.CASCADE,null=True)
        diploma = models.ImageField(upload_to='diplomas', null=True, blank=True)
        dipmoma_status=models.CharField(default="untreated",max_length=20)
        is_approved=models.BooleanField(default=0)

       
     
    









def verif_password(pswd):
    if len(pswd) <= 8:
        return "Password must be at least 8 characters long."
    if not re.search(r'[A-Z]', pswd):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[!@#$%^&*()_+\-=[\]{};':\"\\|,.<>/?]", pswd):
        return "Password must contain at least one special character."
    return "valid"


@csrf_exempt
@api_view(["POST"])
def validate_password(request):
    if request.method == "POST":
        body_unicode = request.body.decode('utf-8')
        body = json.loads(body_unicode)
        password = body.get('password')

        # Validate the password
        password_verification = verif_password(password)
        return JsonResponse({"message": password_verification})


@csrf_exempt
@api_view(["POST"])
def sign_up(request):
    if request.method == "POST":
        body_unicode = request.body.decode('utf-8')
        body = json.loads(body_unicode)
        email = body.get('email')
        password = body.get('password')
        username = body.get('username')
        role = body.get('role')
        gender = body.get('gender')

        # Validate the password
        password_verification = verif_password(password)
        if password_verification != "valid":
            return HttpResponse(password_verification)

        try:
            user = User.objects.create_user(email=email, password=password, username=username, role=role, gender=gender,is_active=False)
           
            # Generate a verification token
            token = default_token_generator.make_token(user)

            # Send the verification email to the user
            send_verification_email(email, token, request)
            
            return HttpResponse('An email verification link has been sent. Please check your email to activate your account.')
        except Exception as e:
            if User.objects.filter(email=email).exists():
                return HttpResponse('This email is already in use.')
            return HttpResponse(str(e))

def send_verification_email(user_email, token, request):
    current_site = get_current_site(request)
    domain = current_site.domain
    verification_link = reverse('verify_email', kwargs={'email_b64': urlsafe_base64_encode(force_bytes(user_email)), 'token': token})
    subject = 'Activate Your Account'
    message = f'Click the following link to activate your account: http://{domain}{verification_link}'
    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user_email], fail_silently=False)

@csrf_exempt
@api_view(["GET"])
def verify_email(request, email_b64, token):
    try:
        email = force_str(urlsafe_base64_decode(email_b64))
        user = User.objects.get(email=email)

        if default_token_generator.check_token(user, token):
            user.is_active = True  # Activate the user's account
            user.save()
            doctor = Doctors.objects.create(doctor_id=user)

                       
            
            return HttpResponse('Email verified successfully. Your account has been activated.')
        else:
            return HttpResponse('Invalid verification link.')
    except User.DoesNotExist:
        return HttpResponse('User not found.')
# Log in an existing user


@csrf_exempt
def log_in(request):
    if request.method == "POST":
        body_unicode = request.body.decode('utf-8')
        body = json.loads(body_unicode)
        email = body.get('email')
        password = body.get('password')

        try:
            user = authenticate(request, email=email, password=password)
            print("User object after authentication:", user)  # Debugging

            if user is not None:
                print("User activation status:", user.is_active)  # Debugging

                if user.is_active:
                    # Your existing code
                    print("User authenticated successfully")
                    now = datetime.utcnow()
                    valid_tokens = BlacklistToken.objects.filter(Q(user=user))

                    if valid_tokens.exists():
                        return JsonResponse({'msg': "User already logged in."}, status=400)

                    payload = {
                        'user_id': user.pk,
                        'email': user.email,
                        'username': user.username,
                        'id': user.id,
                        'heart_rate': user.heart_rate,
                        'number_connect': user.number_connect,
                        'role': user.role,
                        'profile_picture': user.profile_picture.url if user.profile_picture else None
                    }
                    token = jwt.encode(payload, "riadh", algorithm='HS256')

                    BlacklistToken.objects.create(user=user, token=token)
                    user.number_connect += 1
                    user.save()

                    return JsonResponse({'msg': "connected successfully", 'token': token})
                else:
                    return JsonResponse({'msg': "Please verify your account."}, status=401)
            else:
                print("User authentication failed")
                return JsonResponse({'msg': "Invalid email or password"}, status=401)

        except Exception as e:
            print(e)
            return JsonResponse({'msg': "An error occurred while trying to log in"}, status=500)



@api_view(['POST'])
def upload_diploma(request, idd):
    try:
        doctor = Doctors.objects.get(doctor_id=idd)
    except ObjectDoesNotExist:
        return JsonResponse({"message": "Doctor not found"}, status=404)

    diploma = request.FILES.get('diplomas')
    if diploma:
        doctor.diploma = diploma
        doctor.save()
        return JsonResponse({"message": "Diploma uploaded wait until the admin verify your identity"})
    else:
        return JsonResponse({"message": "No diploma provided"}, status=400)


@api_view(["GET"])
def check_doctor_approval(request, doctor_id):
    try:
        doctor = Doctors.objects.get(doctor_id=doctor_id)
        is_approved = doctor.is_approved  # Assuming you have a field 'is_approved' in your Doctor model
        return JsonResponse({"is_approved": is_approved})
    except Doctors.DoesNotExist:
        return JsonResponse({"message": "Doctor not found"}, status=404)



from django.http import JsonResponse

@api_view(['GET'])
def get_doctor_requests(request):
    # Fetch doctor approval requests
    requests = Doctors.objects.filter(is_approved=False)

    # Prepare a list of dictionaries containing relevant data
    requests_data = [
        {
            'doctor_id': request.doctor_id.id,
            'diploma': request.diploma.url,
            'approval_status': 'Pending' if not request.is_approved else 'Disapproved',
        }
        for request in requests
    ]

    return JsonResponse(requests_data, safe=False)


@api_view(['GET'])
def count_requests(request):
    try:
        count = Doctors.objects.filter(is_approved=False).count()
        return JsonResponse({"count": count})
    except Exception as e:
        return JsonResponse({"message": str(e)}, status=500)

@api_view(['POST'])
def approve_doctor(request, doctor_id):
    try:
        doctor = Doctors.objects.get(doctor_id=doctor_id)
        doctor.is_approved = True
        doctor.dipmoma_status="treated"
        doctor.save()
        user = User.objects.get(id=doctor_id)

        send_mail(
            "Your request to join our community",
            "Dear Mr/Mrs" + "" +user.username+", your request to join the Carenet community has been accepted,welcome Dr."+user.username+" to our community.",
            "your@example.com",  
            [user.email],  
        )
       
        return Response({"message": "Doctor approved"})
    except Doctors.DoesNotExist:
        return Response({"message": "Doctor not found"}, status=404)

@api_view(['DELETE'])
def disapprove_doctor(request, doctor_id):
    try:
        doctor = Doctors.objects.get(doctor_id=doctor_id)
        user = User.objects.get(id=doctor_id)

        send_mail(
            "Your request to join our community",
            f"Dear Mr/Mrs {user.username}, your request to join the Carenet community has unfortunately been refused as we studied your files and we came to the conclusion that you are not eligible to be a practicing doctor on our platform. Therefore, your request is rejected. Have a nice day.",
            "your@example.com",  
            [user.email],  
            fail_silently=False,
        )

        doctor.delete()
        user.delete()

        return Response({"message": "Doctor disapproved and request deleted"})
    except Doctors.DoesNotExist:
        return Response({"message": "Doctor not found"}, status=404)


from django.http import HttpResponse

@csrf_exempt
@api_view(['GET'])
def get_diploma_file(request, doctor_id):
    try:
        doctor = Doctors.objects.get(doctor_id=doctor_id)
        diploma_file = doctor.diploma

        # Get the file extension
        file_extension = diploma_file.path.split('.')[-1].lower()

        # Set the appropriate content type based on the file extension
        content_type = None
        if file_extension == 'pdf':
            content_type = 'application/pdf'
        elif file_extension == 'xlsx':
            content_type = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        elif file_extension == 'docx':
            content_type = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        elif file_extension in ('jpg', 'jpeg'):
            content_type = 'image/jpeg'
        elif file_extension == 'png':
            content_type = 'image/png'
        # Add more conditions for other file types

        if content_type:
            # Read the file and return as HttpResponse with the appropriate content type
            with open(diploma_file.path, 'rb') as f:
                response = HttpResponse(f.read(), content_type=content_type)
                response['Content-Disposition'] = f'attachment; filename="{diploma_file.name}"'
                return response
        else:
            return HttpResponse('Unsupported file type', status=400)
    except Doctors.DoesNotExist:
        return HttpResponse('Doctor not found.', status=404)













@api_view(["GET"])
def heart_rate_list(request, idpatient):
    heart_rate_values = []
    try:
        
        vitals = vitalss.objects.filter(user_id=idpatient).order_by('-id')[:20]
        for v in vitals:
            heart_rate_values.append(v.a)
        return JsonResponse(heart_rate_values,safe=False)
    
    except BlacklistToken.DoesNotExist:
        return HttpResponse("patient is not connected")


@api_view(["GET"])
def blood_pressure_list(request, idpatient):
    blood_pressure_values = []
    try:
        
        vitals = vitalss.objects.filter(user_id=idpatient).order_by('-id')[:20]
        for v in vitals:
            blood_pressure_values.append(v.b)
        return JsonResponse(blood_pressure_values,safe=False)
    
    except BlacklistToken.DoesNotExist:
        return HttpResponse("patient is not connected")


@api_view(["GET"])
def fbs_list(request, idpatient):
    fbs_values = []
    try:
        
        vitals = vitalss.objects.filter(user_id=idpatient).order_by('-id')[:20]
        for v in vitals:
            fbs_values.append(v.c)
        return JsonResponse(fbs_values,safe=False)
    
    except BlacklistToken.DoesNotExist:
        return HttpResponse("patient is not connected")


@api_view(["GET"])
def cholesterol_list(request, idpatient):
    cholesterol_values = []
    try:
        
        vitals = vitalss.objects.filter(user_id=idpatient).order_by('-id')[:20]
        for v in vitals:
            cholesterol_values.append(v.d)
        return JsonResponse(cholesterol_values,safe=False)
    
    except BlacklistToken.DoesNotExist:
        return HttpResponse("patient is not connected")


    

    



    


    
    
            


#update details 
@permission_classes([IsAuthenticated])
@api_view(['POST'])
def updatedetails(request, idd):
    age = request.data.get('age')
    height = request.data.get('height')
    weight = request.data.get('weight')

    try:
        user = User.objects.get(id=idd)
        user.age = age
        user.height = height
        user.weight = weight

        profile_picture = request.FILES.get('profile_picture')
        if profile_picture:
            user.profile_picture = profile_picture

        user.save()

        return JsonResponse({"message": "Details updated"})
    except User.DoesNotExist:
        return JsonResponse({"message": "User not found"})






@api_view(['GET'])

def get_details(request, user_id):
    try:
        user = User.objects.get(id=user_id)
        data = {
            "age": user.age,
            "weight": user.weight,
            "height": user.height,
        }
        return JsonResponse(data)
    except User.DoesNotExist:
        return JsonResponse({"error": "User details not found"}, status=404)        

    


from django.core.exceptions import ObjectDoesNotExist

@permission_classes([IsAuthenticated])
@api_view(['POST'])
def update_profile_picture(request, idd):
    try:
        user = User.objects.get(id=idd)
    except ObjectDoesNotExist:
        return JsonResponse({"message": "User not found"}, status=404)

    profile_picture = request.FILES.get('profile_picture')
    if profile_picture:
        user.profile_picture = profile_picture
        user.save()
        return JsonResponse({"message": "Profile picture updated"})
    else:
        return JsonResponse({"message": "No profile picture provided"}, status=400)


def get_profile_picture(request, user_id):
    try:
        user = User.objects.get(id=user_id)
        profile_picture = user.profile_picture

        # Assuming you are storing the profile pictures in the media folder
        # You need to adjust the path accordingly if you store the images in a different location.
        image_path = f'media/{profile_picture}' 
        with open(image_path, 'rb') as f:
            return HttpResponse(f.read(), content_type='image/jpeg')
    except User.DoesNotExist:
        # If the user with the given ID does not exist, you can return a default image or a 404 error.
        return HttpResponse('Profile picture not found.', status=404)


@permission_classes(IsAuthenticated)
@api_view(['POST'])
def increment(request):
    
        all= BlacklistToken.objects.all()
        for one in all:
             idd=one.user_id
             data=User.objects.get(id=idd)
             data.number_connect+=1
             data.save()
             return JsonResponse({'msg':"incremented"})


    
# Log out the current user
@api_view(['POST'])
@authentication_classes([])
@permission_classes([])

def log_out(request, id):
    try:
        token = BlacklistToken.objects.filter(user_id=id)
        token.delete()
        logout(request)
        return JsonResponse({'msg': "disconnected successfully"})
    except BlacklistToken.DoesNotExist:
        return JsonResponse({'msg': "Invalid user ID or user not logged in."}, status=400)
    except Exception as e:
        print(e)
        return JsonResponse({'msg': "An error occurred while trying to log out."}, status=500)


# Reset the user's password
@csrf_exempt
def reset_password(request):
    if request.method == "POST":
        body_unicode = request.body.decode('utf-8')
        body = json.loads(body_unicode)
        email = body.get('email')
        try:
            #auth.send_password_reset_email(email)
            response_data = {"success": True, "message": "A password reset email has been sent to your email address."}
        except requests.exceptions.HTTPError as e:
            response_data = {"success": False, "message": str(e)}

        # Return response as JSON
        return JsonResponse(response_data)

    else:
        response_data = {"success": False, "message": "Invalid request method."}
        return JsonResponse(response_data)
    
@api_view(["GET"])
def get_users(request):
    users=User.objects.all()
    return JsonResponse({'users':users})


@api_view((["GET"]))
def patient_list(request):
    plist=[]
    users=User.objects.filter(role="Patient")
    for user in users:
        plist.append(user.username)
    return JsonResponse(plist,safe=False)


@api_view((["GET"]))
def doctor_list(request):
    dlist=dict()
    users=User.objects.filter(role="Doctor")
    for user in users:
        dlist[user.username]=user.id
        
        
    return JsonResponse(dlist,safe=False)



@api_view((["GET"]))
def patient_list(request):
    plist=dict()
    users=User.objects.filter(role="Patient")
    for user in users:
        plist[user.username]=user.id
        
        
    return JsonResponse(plist,safe=False)


@api_view((["DELETE"]))
def deleteuser(request,iduser):
   
    user=User.objects.filter(id=iduser)
    user.delete()
    return JsonResponse({"msg":"user deleted"})


@api_view((["GET"]))
def checksuperuser(request,idd):

    
    
             
        data=User.objects.get(id=idd)
        if data.is_superuser==1:
                data.role='admin'
                data.save()
                return JsonResponse({'msg':1})
        else:
                return JsonResponse({'msg':0})


@api_view((["GET"]))
def checkifdoctor(request,idd):

    
    
             
        data=User.objects.get(id=idd)
        if data.role=="Doctor":
                
                return JsonResponse({'msg':"yes"})
        else:
                return JsonResponse({'msg':"no"})

@api_view(["POST"])
def addpatient(request, iddoctor, idpatient):
    try:
        doctor = User.objects.get(role="Doctor", id=iddoctor)
        patient = User.objects.get(role="Patient", id=idpatient)
        treatment.objects.create(
            doctor=doctor,
            patient=patient
        )
        return Response(status=status.HTTP_201_CREATED)
    except User.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)


@api_view(['GET'])
def checkiftreatment(request, iddoctor, idpatient):
    treatments = treatment.objects.filter(doctor_id=iddoctor, patient_id=idpatient)
    if treatments.exists():
        return JsonResponse({'msg': 'yes'})
    else:
        return JsonResponse({'msg': 'no'})


@api_view(((["GET"])))
def getmypatients(request,iddoctor):
    all=treatment.objects.filter(doctor_id=iddoctor)
    results=dict()
    for one in all:
        idpatient=one.patient_id
        patient=User.objects.filter(id=idpatient).get()
          
        results[patient.username]=patient.id
    return JsonResponse(results,safe=False)


@api_view((["DELETE"]))
def deletemypatient(request,iddoctor,idpatient):
    treat=treatment.objects.filter(doctor_id=iddoctor).filter(patient_id=idpatient)
    treat.delete()
    return JsonResponse({'msg':"this patient is deleted from your patients list"})

@api_view(["GET"])
def getmydoctors(request, idpatient):
    all_treatments = treatment.objects.filter(patient_id=idpatient)
    results = []
    for treatment_obj in all_treatments:
        doctor_id = treatment_obj.doctor_id
        doctor = User.objects.get(id=doctor_id)
        doctor_data = {
            "id": doctor_id,
            "username": doctor.username,
            "email": doctor.email
        }
        results.append(doctor_data)
    return JsonResponse(results, safe=False)

  
              




@api_view((["GET"]))
def search(request):
    search_term = request.GET.get('search')
    users = User.objects.filter(Q(username__icontains=search_term) | Q(email__icontains=search_term))
    results = [{'id': user.id, 'name': user.username} for user in users]
    return JsonResponse(results, safe=False)


  
@api_view((["POST"]))
def send_message(request,idsender,idreciever):
     sender = User.objects.get( id=idsender)
     reciever = User.objects.get( id=idreciever)
     if request.method == "POST":
        body_unicode = request.body.decode('utf-8')
        body = json.loads(body_unicode)
        msg= body.get('message')
        
        message.objects.create(content=msg,sender=sender,reciever=reciever)
        return JsonResponse({'msg':'message sent'})


@api_view(["GET"])
def get_messages(request, idsender, idreciever):
    try:
        sender = User.objects.get(id=idsender)
        reciever = User.objects.get(id=idreciever)
        
        messages = message.objects.filter(sender=sender, reciever=reciever) | message.objects.filter(sender=reciever, reciever=sender)
        
        message_list = []
        for msg in messages:
            message_list.append({
               
                "content": msg.content,
                "sender": msg.sender.username,
                "reciever": msg.reciever.username,
                #"timestamp": msg.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            })
        
        return JsonResponse({"messages": message_list})
    except User.DoesNotExist:
        return JsonResponse({"error": "User does not exist"}, status=400)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

        

    
@api_view(["POST"])
def add_notification(request,idpatient):
     body_unicode = request.body.decode('utf-8')
     body = json.loads(body_unicode)
     content= body.get('content')
     patient = User.objects.get( id=idpatient)
    
    
       
        
     notifications.objects.create(content=content,patient_id=patient)
     return JsonResponse({'msg':'notification sent'})



from django.core import serializers

@api_view(["GET"])
def get_notifications(request, idpatient):
    # Retrieve the notifications for the given patient ID
    Notifications = notifications.objects.filter(patient_id=idpatient).order_by('-time')
    
    # Create a list to store the notification data
    notification_list = []
    
    # Iterate over the notifications and extract the content and time
    for notification in Notifications:
        notification_data = {
            "content": notification.content,
            "time": notification.time.strftime("%Y-%m-%d %H:%M:%S")  # Format the time as desired
        }
        notification_list.append(notification_data)
    
    # Return the list of notification dictionaries as a response
    return JsonResponse(notification_list, safe=False)








import pickle
@api_view(["GET"])
def predict_view(request, age, sex, heart_rate, fbs, chol):
    # Load the serialized KNN model
    with open('C:/Users/riadh/OneDrive/Documents/happy/model.pkl', 'rb') as file:
        knn_model = pickle.load(file)

    # Get additional data if needed
    thalach = random.randint(50,150)

    # Preprocess the input data if needed

    # Create a list with the input data
    input_data = [[thalach, fbs, chol, heart_rate, age, sex]]

    # Make predictions using the KNN model
    prediction = knn_model.predict(input_data)

    # Return the prediction as a response
    return HttpResponse(prediction)


@api_view(["GET"])
def getvitals(request, idpatient):
    user = User.objects.get(id=idpatient)
    sex = user.gender
    if sex == 'male':
        sex = 0
    else:
        sex = 1
    age = user.age
    
    vital = vitalss.objects.filter(user_id=idpatient).latest('id')
    chol = vital.d
    fbs = vital.c
    blood_pressure = vital.b
    heart_rate = vital.a
    
    l = [age, sex, heart_rate, fbs, chol]
    
    return JsonResponse(l, safe=False)

@api_view(["POST"])
def add_appointment(request, iddoctor, idpatient):
    body_unicode = request.body.decode("utf-8")
    body = json.loads(body_unicode)
    date_str = body.get("date")

    try:
        # Parse the date string into a datetime object
        date = datetime.fromisoformat(date_str)
        user=User.objects.get(id=idpatient)
        doctor=User.objects.get(id=iddoctor)
        send_mail("new appointment", "Dear " + user.username + ", you have a new appointment with Dr. " + doctor.username + " at " + date_str, "carenet@carenet.tn", [user.email])

        # Create the appointment with the correct doctor and patient IDs
        appointment.objects.create(date=date, doctor_id=iddoctor, patient_id=idpatient)

        return JsonResponse({"msg": "Appointment created successfully"})
    except Exception as e:
        return JsonResponse({"msg": str(e)}, status=400)




@api_view(["GET"])
def get_appointments(request, iddoctor):
    try:
        # Filter appointments based on the doctor's ID
        appointments = appointment.objects.filter(doctor_id=iddoctor)
        
        # Serialize the appointments to return as JSON response
        serialized_appointments = [
            {
                "id": app.id,
                "date": app.date.strftime("%Y-%m-%dT%H:%M:%S"),  # Include the time part in the date
                "patient_id": app.patient_id,
                "patient_username": app.patient.username,
            }
            for app in appointments
        ]
        
        return JsonResponse({"appointments": serialized_appointments})
    
    except Exception as e:
        return JsonResponse({"msg": str(e)}, status=400)



@api_view(["GET"])
def get_appointments_patient(request, idpatient):
    try:
        # Filter appointments based on the doctor's ID
        appointments = appointment.objects.filter(patient_id=idpatient)
        
        # Serialize the appointments to return as JSON response
        serialized_appointments = [
            {
                "id": app.id,
                "date": app.date.strftime("%Y-%m-%dT%H:%M:%S"),  # Include the time part in the date
                "doctor_id": app.doctor_id,
                "doctor_username": app.doctor.username,
            }
            for app in appointments
        ]
        
        return JsonResponse({"appointments": serialized_appointments})
    
    except Exception as e:
        return JsonResponse({"msg": str(e)}, status=400)




@api_view(["DELETE"])

def deleteappointment(request,iddoctor,idapp):
            Appointment = appointment.objects.filter(doctor_id=iddoctor,id=idapp)
            try:
                Appointment.delete()
                return JsonResponse({'msg':'appointment deleted'})
            except:
                return JsonResponse({'msg':'error while deleting'})


