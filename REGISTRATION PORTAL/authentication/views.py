from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.core.mail import EmailMessage, send_mail
from registration import settings
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth import authenticate, login, logout
from . tokens import generate_token

# Create your views here.
def home(request):
    return render(request,"authentication/index.html")

def signup(request):
    if request.method=="POST":
        username=request.POST["username"]
        fname=request.POST["fname"]
        lname=request.POST["lname"]
        email=request.POST["email"]
        passw=request.POST["passw"]
        cp=request.POST["cp"]

        #username already exists

        if User.objects.filter(username=username):
            messages.error(request,"Username already exists. Try some other username")
            return redirect('home')

        # email already exists
            
        if User.objects.filter(email=email):
            messages.error(request,"EMAIL ALREADY REGISTERED. TRY ANOTHER EMAIL")
            return redirect('home')

        if len(username)>10:
            messages.error(request,"Username must be less than 10 characters")
            return redirect('home')

        if len(username)<4:
            messages.error(request,"Username must be at least 4 characters")
            return redirect('home')

        if passw!=cp:
            messages.error(request,"PASSWORD MUST MATCH")
            return redirect('home')

        if not username.isalnum():
            messages.error(request,"username must be alphanumeric")
            return redirect('home')

        myuser=User.objects.create_user(username,email,passw)
        myuser.first_name=fname
        myuser.last_name=lname
        myuser.is_active = False
        myuser.save()

        messages.success(request,"Your acc has been successfully created. We have also sent you a confirmation email")

        #WELCOME EMAIL

        subject = "EMAIL VERIFICATION CHECK MAIL !"
        message = "HELLO "+ myuser.first_name + "!! \n" + "Welcome to OUR PORTAL  \n ThankYou for showing interest We have also sent u a confirmation email, please confirm your email address to proceed. \n Thanking You Sainik"
        from_email = settings.EMAIL_HOST_USER
        to_list = [myuser.email]
        send_mail(subject, message, from_email, to_list, fail_silently=True)

        #EMAIL ADDRESS CONFIRMATION

        current_site = get_current_site(request)
        email_subject="CONFIRM YOUR EMAIL- REGISTER PORTAL LOGIN"
        message2= render_to_string('email_confirmation.html',{
            'name': myuser.first_name,
            'domain': current_site.domain,
            'uid':urlsafe_base64_encode(force_bytes(myuser.pk)),
            'token': generate_token.make_token(myuser)
        })
        email = EmailMessage(
        email_subject,
        message2,
        settings.EMAIL_HOST_USER,
        [myuser.email],
        )
        email.fail_silently = True
        email.send()

        return redirect('signin')
    
    
    
    return render(request,"authentication/signup.html")

def activate(request,uidb64,token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        myuser = User.objects.get(pk=uid)
    except (TypeError,ValueError,OverflowError,User.DoesNotExist):
        myuser = None

    if myuser is not None and generate_token.check_token(myuser,token):
        myuser.is_active = True
        # user.profile.signup_confirmation = True
        myuser.save()
        login(request,myuser)
        messages.success(request, "Your Account has been activated!!")
        return redirect('signin')
    else:
        return render(request,'activation_failed.html')

def signin(request):

    if request.method=='POST':
        username=request.POST["username"]
        passw=request.POST["passw"]

        user= authenticate(username=username, password=passw)

        if user is not None:
            login(request,user)
            fname=user.first_name
            return render(request, "authentication/index.html",{'fname':fname}) 
        else:
            messages.error(request,"Bad Credentials !")

    return render(request,"authentication/signin.html")

def signout(request):
    logout(request)
    messages.success(request,"Logged out successfully")  
    return redirect('home')  