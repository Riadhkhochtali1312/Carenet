from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.postgres.fields import ArrayField



# Create your models here.
class User(AbstractUser):
    name = models.CharField(max_length=255)
    email = models.EmailField(('email address'), null=True, blank=True,unique=True)
    password = models.CharField(max_length=255)
    username = models.CharField(max_length=255,unique=False)
    role=models.CharField(max_length=20,default='')
    age = models.IntegerField(default=0)
    weight = models.IntegerField(default=0)
    height=models.IntegerField(default=0)

    number_connect = models.IntegerField(default=0)
    gender=models.CharField(max_length=4,default='')
    heart_rate = models.IntegerField(default=0)
    blood_pressure=models.IntegerField(default=0)
    fbs= models.IntegerField(default=0)
    cholesterol=models.IntegerField(default=0)
    profile_picture = models.ImageField(upload_to='profile_pictures', null=True, blank=True)
   

    

    
    USERNAME_FIELD = 'email'
    
    REQUIRED_FIELDS = []

class vitalss(models.Model):
        #for heart rate
        a = models.IntegerField()
        #for blood pressure
        b = models.IntegerField()
        #for fasting blood sugar(fbs)
        c=models.IntegerField(default=0)
        #for cholesterol
        d=models.IntegerField(default=0)
        user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='vitals')
        updated_at = models.DateTimeField(auto_now=True)
        objects = models.Manager ()  # default manager

    
   
