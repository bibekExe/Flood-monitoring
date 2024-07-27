from django.shortcuts import redirect,render
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login

from django.views.decorators.csrf import csrf_protect
from login import settings

from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.template.loader import render_to_string
from django.core.mail import EmailMessage
from django.conf import settings
from oauth2client.client import OAuth2WebServerFlow, AccessTokenCredentials
from .forms import  SetPasswordFormCustom  # type: ignore # Make sure to import your custom forms



# Create your views here.
def home(request):
    return render(request, 'authentication/index.html')

def next_home(request):
    return render(request, 'index.html')

def alert(request):
    return render(request, 'alert.html')

def signup(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        fname = request.POST.get('fname')
        lname = request.POST.get('lname')
        email = request.POST.get('email')
        pass1 = request.POST.get('pass1')
        pass2 = request.POST.get('pass2')

        if User.objects.filter(username=username):
            messages.error(request, 'Username already exists')
            return redirect('signup')

        if User.objects.filter(email=email):
            messages.error(request, 'Email already exists')
            return redirect('signup')

        if len(username) > 15:
            messages.error(request, 'Username must be under 15 characters')
            return redirect('signup')

        if pass1 != pass2:
            messages.error(request, 'Passwords did not match')
            return redirect('signup')

        if not username.isalnum():
            messages.error(request, 'Username must be alphanumeric!')
            return redirect('signup')

        myuser = User.objects.create_user(username, email, pass1)
        myuser.first_name = fname
        myuser.last_name = lname
        myuser.save()

        messages.success(request, "Your account has been successfully created.")
        return redirect('signin')

    return render(request, 'authentication/signup.html')

def signin(request):
    if request.method == 'POST':
        username = request.POST['username']
        pass1 = request.POST['pass1']

        user = authenticate(username=username, password=pass1)

        if user is not None:
            login(request, user)
            fname = user.first_name
            return render(request, "index.html", {'fname': fname})
        else:
            messages.error(request, "Bad Credentials!")
            return redirect('home')

    return render(request, 'authentication/signin.html')

def google_auth(request):
    flow = OAuth2WebServerFlow(
        client_id=settings.GOOGLE_CLIENT_ID,
        client_secret=settings.GOOGLE_CLIENT_SECRET,
        scope='https://mail.google.com/',
        redirect_uri='http://localhost:8000/oauth2callback'
    )
    auth_uri = flow.step1_get_authorize_url()
    return redirect(auth_uri)

def oauth2callback(request):
    flow = OAuth2WebServerFlow(
        client_id=settings.GOOGLE_CLIENT_ID,
        client_secret=settings.GOOGLE_CLIENT_SECRET,
        scope='https://mail.google.com/',
        redirect_uri='http://localhost:8000/oauth2callback'
    )
    credentials = flow.step2_exchange(request.GET['code'])
    request.session['credentials'] = credentials.to_json()
    return redirect('home')

# Password reset views
def password_reset_request(request):
    if request.method == "POST":
        form =SetPasswordFormCustom(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            associated_users = User.objects.filter(email=email)
            if associated_users.exists():
                for user in associated_users:
                    subject = "Password Reset Requested"
                    email_template_name = "password_reset_email.html"
                    c = {
                        "email": user.email,
                        'domain': 'example.com',
                        'site_name': 'Your Site',
                        "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                        "user": user,
                        'token': default_token_generator.make_token(user),
                        'protocol': 'http',
                    }
                    email = render_to_string(email_template_name, c)
                    try:
                        send_email = EmailMessage(subject, email, settings.DEFAULT_FROM_EMAIL, [user.email])
                        send_email.send()
                    except Exception as e:
                        return redirect("/password-reset/done/")
            return redirect("/password-reset/done/")
    form = SetPasswordFormCustom()
    return render(request=request, template_name="password_reset.html", context={"form": form})

def password_reset_confirm(request, uidb64=None, token=None):
    if request.method == 'POST':
        form = SetPasswordFormCustom(user=request.user, data=request.POST)
        if form.is_valid():
            form.save()
            return redirect('password_reset_complete')
    else:
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            form = SetPasswordFormCustom(user)
        else:
            form = None

    return render(request, 'password_reset_confirm.html', {'form': form})




