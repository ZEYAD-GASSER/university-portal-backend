# accounts/api.py

from ninja_extra import NinjaExtraAPI
from ninja_jwt.controller import NinjaJWTDefaultController
from django.shortcuts import get_object_or_404
from ninja import Schema, Router
from ninja.errors import HttpError
from django.conf import settings
from datetime import datetime, timedelta
import jwt
from accounts.models import Student, Registration_Request, Admin
from .auth import JWTAuth
from .tokens import generate_reset_token, create_password_reset_token, verify_token
from compsuggs.api import router as compsuggs_router  # Import compsuggs router
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.contrib.auth.hashers import check_password
import logging

# Set up logging
logger = logging.getLogger(__name__)

router = Router()
api = NinjaExtraAPI()
api.register_controllers(NinjaJWTDefaultController)  # JWT controller
api.add_router("/compsuggs/", compsuggs_router)
api.add_router("/", router)  # ← ✅ Add this line to register the `router`

auth = JWTAuth()
SECRET_KEY = settings.SECRET_KEY

class UserLoginSchema(Schema):
    email: str
    password: str

class PasswordResetSchema(Schema):
    password: str
    token: str

class AdminLoginSchema(Schema):
    email: str
    password: str

class UserRequestSchema(Schema):
    name: str
    email: str
    phone_number: str
    Seat_Number: str
    level: str
    department: str

class AddStudentSchema(Schema):
    name: str
    email: str
    phone_number: str
    Seat_Number: str
    level: str
    department: str   

@api.post("/login_student")
def Slogin(request, data: UserLoginSchema):
    try:
        student = Student.objects.get(email = data.email)
        if check_password(data.password, student.password):
            payload = {
                "id": student.id,
                "email": student.email,
                "exp": datetime.utcnow() + timedelta(minutes=60)
            }
            token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
            try:
                subject = 'Welcome to Our Platform'
                message = f'Dear user email sent successfully...'
                email_from = settings.EMAIL_HOST_USER
                recipient_list = [data.email]
                result = send_mail(subject, message, email_from, recipient_list, fail_silently=True)
            except Exception as e:
                logger.error(f"Email sending error for {user_email}: {str(e)}")
                return False
            return {"token": token, "message": "Login successful"}
        else:
            raise HttpError(401, "Invalid password")
    except Student.DoesNotExist:
        raise HttpError(404, "User not found")

@api.post("/login_admin")
def Alogin(request, data: AdminLoginSchema):
    try:
        admin = Admin.objects.get(email = data.email)
        if check_password(data.password, admin.password):
            payload = {
                "id": admin.id,
                "email": admin.email,
                "exp": datetime.utcnow() + timedelta(minutes=60)
            }
            token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
            return {"token": token, "message": "Login successful"}
        else:
            raise HttpError(401, "Invalid password")
    except Admin.DoesNotExist:
        raise HttpError(404, "User not found")

@api.post("/new_password")
def new_password(request, data: PasswordResetSchema):
    user = verify_token(data.token)
    if user is None:
        raise HttpError(400, "Invalid or expired token")
    try:
        user.password = make_password(data.password)
        user.password_reset_token = None
        user.reset_token_created_at = None
        user.save()
        return {"message": "Password changed successfully"}
    except Student.DoesNotExist:
        raise HttpError(404, "User not found")

@api.post("/submit_request")
def submit_request(request, data: UserRequestSchema):
    if Student.objects.filter(email=data.email).exists():
        raise HttpError(409, "A student with this email already exists.")
    if Student.objects.filter(Seat_Number= data.Seat_Number).exists():
        raise HttpError(409, "A student with this Seat number already exists.")
    try:
        Registration_Request.objects.create(
            name=data.name,
            email=data.email,
            phone_number=data.phone_number,
            Seat_Number=data.Seat_Number,
            level=data.level,
            department=data.department
        )
        return {"message": "Request saved successfully"}
    except Exception as e:
        raise HttpError(400, f"Failed to save request: {str(e)}")

@api.get("/get_all_requests")
def get_all_requests(request):
    requests = Registration_Request.objects.all()
    data = [
        {
            "id": req.id,
            "FullName": req.name,
            "PhoneNumber": req.phone_number,
            "AcademicEmail": req.email,
            "SeatNumber": req.Seat_Number,
            "Level": req.level,
            "Department": req.department
        }
        for req in requests
    ]
    return data

def send_welcome_email(user_email, user_name, reset_token):
    """
    Send welcome email with proper error handling
    """
    try:
        reset_link = f"https://university-portal-frontend-1.vercel.app/new_password?token={reset_token}"
        subject = 'Welcome to Our Platform'
        message = f'Dear {user_name},\n\nYour account has been accepted! Here is the password reset link:\n{reset_link}\n\nThank you for joining us.'
        email_from = settings.EMAIL_HOST_USER
        recipient_list = [user_email]
        result = send_mail(subject, message, email_from, recipient_list, fail_silently=True)
        
    except Exception as e:
        logger.error(f"Email sending error for {user_email}: {str(e)}")
        return False

@api.post("/add_user")
def add_user(request, data: UserRequestSchema):
    logger.info(f"Received add_user request: {data.email}")
    
    if Student.objects.filter(email=data.email).exists():
        logger.warning(f"User with email {data.email} already exists")
        raise HttpError(409, "A student with this email already exists.")
    if Student.objects.filter(Seat_Number=data.Seat_Number).exists():
        logger.warning(f"User with seat number {data.Seat_Number} already exists")
        raise HttpError(409, "A student with this Seat number already exists.")
    
    try:
        # First, create the user
        user = Student.objects.create(
            name=data.name,
            email=data.email,
            phone_number=data.phone_number,
            Seat_Number=data.Seat_Number,
            level=data.level,
            department=data.department
        )
        logger.info(f"User created successfully: {user.id} - {user.email}")
        
        # Generate password reset token
        token = create_password_reset_token(user)
        
            
    except Exception as e:
        logger.error(f"Error in add_user for {data.email}: {str(e)}")
        raise HttpError(400, f"Failed to add user: {str(e)}")

@api.delete("/delete_request/{request_id}")
def delete_request(request, request_id: int):
    logger.info(f"Received delete request for ID: {request_id}")
    try:
        obj = get_object_or_404(Registration_Request, id=request_id)
        obj.delete()
        logger.info(f"Request {request_id} deleted successfully")
        return {"message": "Request deleted successfully"}
    except Exception as e:
        logger.error(f"Error deleting request {request_id}: {str(e)}")
        raise HttpError(400, f"Failed to delete request: {str(e)}")

# Add a test endpoint to check email configuration
@api.post("/test_email")
def test_email(request):
    """Test endpoint to check if email is working"""
    try:
        result = send_mail(
            'Test Email',
            'This is a test email from Django.',
            settings.EMAIL_HOST_USER,
            [settings.EMAIL_HOST_USER],  # Send to yourself
            fail_silently=False
        )
        return {"message": "Email test successful", "result": result}
    except Exception as e:
        return {"message": f"Email test failed: {str(e)}", "result": 0}