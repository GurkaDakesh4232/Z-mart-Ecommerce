from django.shortcuts import render, HttpResponse, redirect
from django.contrib.auth.models import User
from django.views.generic import View
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.urls import reverse
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_str, DjangoUnicodeDecodeError
from django.core.mail import EmailMessage
from django.conf import settings
import threading
from django.urls import reverse

# Token Generators
from django.contrib.auth.tokens import PasswordResetTokenGenerator

# Custom Token Generator (if you have any)
from .utils import TokenGenerator, generate_token

# Thread class to send email asynchronously
class EmailThread(threading.Thread):
    def __init__(self, email_message):
        self.email_message = email_message
        threading.Thread.__init__(self)

    def run(self):
        self.email_message.send()

# Signup view
def signup(request):
    if request.method == "POST":
        email = request.POST['email']
        password = request.POST['password']
        confirm_password = request.POST['confirmPassword']

        if password != confirm_password:
            messages.warning(request, "Passwords do not match")
            return render(request, 'auth/signup.html')

        if User.objects.filter(email=email).exists():
            messages.warning(request, "Email is already taken")
            return render(request, 'auth/signup.html')

        # Create the user
        user = User.objects.create_user(username=email, email=email, password=password)
        user.is_active = False  # Deactivate account until email verification
        user.save()

        # Prepare the email
        current_site = get_current_site(request)
        email_subject = "Activate your Account"
        activation_link = reverse('drkauth:activate', kwargs={
            'uidb64': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': generate_token.make_token(user),
        })

        # Full activation URL
        full_activation_link = f"http://{current_site.domain}{activation_link}"

        # Render the email body with the full activation link
        email_body = render_to_string('auth/activate.html', {
            'user': user,
            'activation_link': full_activation_link
        })

        # Send the email
        email_message = EmailMessage(email_subject, email_body, settings.EMAIL_HOST_USER, [email])
        EmailThread(email_message).start()

        messages.info(request, "Activate your account by clicking the link in your email")
        return redirect('/drkauth/login/')

    return render(request, 'auth/signup.html')

class ActivateAccountView(View):
    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and generate_token.check_token(user, token):
            user.is_active = True
            user.save()
            messages.info(request, "Account activated successfully!")
            return redirect('/drkauth/login/')
        
        messages.error(request, "Activation link is invalid!")
        return render(request, 'auth/activatefail.html')

# Login handler view
def handlelogin(request):
    if request.method == "POST":
        username = request.POST['email']
        userpassword = request.POST['password']
        myuser = authenticate(username=username, password=userpassword)

        if myuser is not None:
            login(request, myuser)
            messages.success(request, "Login successful")
            return redirect('/')  # Redirect to home page or dashboard

        messages.error(request, "Invalid credentials")
        return redirect('/drkauth/login/')

    return render(request, 'auth/login.html')

# Logout handler view
def handlelogout(request):
    logout(request)
    messages.success(request, "Logout successful")
    return redirect('/drkauth/login/')






class RequestResetEmailView(View):
    def get(self, request):
        return render(request, 'auth/request-reset-email.html')
    
    def post(self, request):
        email = request.POST.get('email')
        user = User.objects.filter(email=email).first()

        if user:
            current_site = get_current_site(request)
            email_subject = "Reset your Password"
            
            # Generate the reset link
            reset_link = reverse('drkauth:set-new-password', kwargs={
                'uidb64': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': PasswordResetTokenGenerator().make_token(user),
            })

            full_reset_link = f"http://{current_site.domain}{reset_link}"

            # Render the email body
            email_body = render_to_string('auth/reset-user-password.html', {
                'user': user,
                'reset_link': full_reset_link
            })
            
            # Create and send the email
            email_message = EmailMessage(email_subject, email_body, settings.EMAIL_HOST_USER, [email])
            EmailThread(email_message).start()

            messages.info(request, "We have sent an email with instructions to reset your password")
        else:
            messages.error(request, "No account found with this email address")
        
        return redirect('/drkauth/request-reset-email/')





class SetNewPasswordView(View):
    def get(self, request, uidb64, token):
        context = {
            'uidb64': uidb64,
            'token': token
        }

        try:
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=user_id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                messages.warning(request, "Password reset link is invalid or expired. Please request a new link.")
                return redirect('drkauth:request-reset-email')
        except (DjangoUnicodeDecodeError, User.DoesNotExist):
            messages.error(request, "Something went wrong. Please try again.")
            return redirect('drkauth:request-reset-email')
        
        return render(request, 'auth/set-new-password.html', context)
    
    def post(self, request, uidb64, token):
        context = {
            'uidb64': uidb64,
            'token': token
        }
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirmPassword')

        if password != confirm_password:
            messages.warning(request, "Passwords do not match")
            return render(request, 'auth/set-new-password.html', context)
        
        try:
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=user_id)

            if PasswordResetTokenGenerator().check_token(user, token):
                user.set_password(password)
                user.save()
                messages.success(request, "Password reset successfully! Please login with your new password.")
                return redirect('/drkauth/login/')
            else:
                messages.error(request, "The reset link is no longer valid. Please request a new one.")
                return redirect('drkauth:request-reset-email')

        except (DjangoUnicodeDecodeError, User.DoesNotExist):
            messages.error(request, "Something went wrong. Please try again.")
            return render(request, 'auth/set-new-password.html', context)

