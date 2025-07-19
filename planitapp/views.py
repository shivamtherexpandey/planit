from django.shortcuts import render
from django.views import View
from django.http import HttpResponse
from django.urls import reverse_lazy
from django.conf import settings
from django.shortcuts import redirect
from dotenv import load_dotenv
from googleapiclient.errors import HttpError
from django.contrib import messages
from google.auth.transport.requests import Request
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth import login
from django.core.paginator import Paginator
import gspread
from datetime import datetime
from django.contrib.auth.models import User
from planitapp.models import SocialToken
from django.db import transaction
import logging
import jwt
import requests
import urllib.parse
import os

load_dotenv()

create_event_logger = logging.getLogger('create_event_logger')
show_event_logger = logging.getLogger('show_event_logger')
general_logger = logging.getLogger('general_logger')

class LoginPage(View):

    def get(self, request, *args, **kwargs):
        
        if request.user.is_authenticated:
            general_logger.info(f'User {request.user.email} is accessing the home page.')
            return redirect("home_page")
        else:
            general_logger.info('User has requested the login page.')
            return render(request, "login.html")


class GoogleLogin(View):

    def get(self, request, *args, **kwargs):
        auth_params = {
            "client_id": os.environ.get("GOOGLE_ACCOUNTS_CLIENT_ID"),
            "redirect_uri": os.environ.get("GOOGLE_REDIRECT_URL"),
            "scope": " ".join(settings.GOOGLE_SCOPE),
            "access_type": "offline",
            "response_type": "code",
            "prompt":"consent"
        }

        encoded_params = urllib.parse.urlencode(auth_params)
        auth_url = f'{os.environ.get("AUTHORIZATION_URL")}?{encoded_params}'
        general_logger.info('User is being redirected to the google auth page.')
        return redirect(auth_url)


def get_public_key(key):
    modulus = int.from_bytes(jwt.utils.base64url_decode(key["n"].encode()), "big")
    exponent = int.from_bytes(jwt.utils.base64url_decode(key["e"].encode()), "big")

    # Create an RSA public key
    public_key = rsa.RSAPublicNumbers(exponent, modulus).public_key(default_backend())

    # Serialize the RSA public key
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return pem


class GoogleAuth(View):

    @transaction.atomic
    def get(self, request, *args, **kwargs):

        auth_code = request.GET.get("code", "")

        if not auth_code:
            return HttpResponse("Error in Accessing User Code.")

        token_params = {
            "code": auth_code,
            "client_id": os.environ.get("GOOGLE_ACCOUNTS_CLIENT_ID"),
            "client_secret": os.environ.get("GOOGLE_ACCOUNTS_CLIENT_SECRET"),
            "redirect_uri": os.environ.get("GOOGLE_REDIRECT_URL"),
            "grant_type": "authorization_code",
        }

        response = requests.post(os.environ.get("GOOGLE_TOKEN_URL"), data=token_params)

        token_data = ""
        if response.status_code == 200:
            token_data = response.json()
            print(token_data)
            general_logger.info(f'Exchange of token was successful, proceeding to login.')
        else:
            return HttpResponse("Token Not Received, Error.")

        google_public_key_url = "https://www.googleapis.com/oauth2/v3/certs"

        response = requests.get(google_public_key_url)
        public_keys = response.json()

        decoded_token = ""
        for key in public_keys["keys"]:
            try:
                public_key = get_public_key(key)
                decoded_token = jwt.decode(
                    token_data.get("id_token"),
                    public_key,
                    algorithms=["RS256"],
                    audience=os.environ.get("GOOGLE_ACCOUNTS_CLIENT_ID"),
                )
            except:
                continue
            else:
                break

        email = decoded_token.get("email")
        first_name = decoded_token.get("given_name")
        last_name = decoded_token.get("family_name")
        profile_picture = decoded_token.get("picture")

        # Get User Object
        user_obj, _ = User.objects.get_or_create(username=email, email=email)
        user_obj.first_name = first_name
        user_obj.last_name = last_name
        user_obj.save()
        general_logger.info('User object is created or retrieved.')

        # Access the SocialToken
        access_token = token_data.get("access_token")
        social_token, created = SocialToken.objects.get_or_create(user=user_obj)

        social_token.access_token = access_token
        social_token.profile_pic_link = profile_picture
        social_token.save()

        # Create Instance
        if "refresh_token" in token_data:
            refresh_token = token_data.get("refresh_token")
            social_token.refresh_token = refresh_token

        social_token.save()
        login(request, user=user_obj)
        general_logger.info(f'User {user_obj.email} login successful.')
        messages.success(request, "Google Account Login Success !")

        return redirect("home_page")


class HomePage(LoginRequiredMixin, View):

    def get_login_url(self):
        return reverse_lazy("launch_page")

    def get(self, request, *args, **kwargs):
        user = request.user
        try:
            social_ac = SocialToken.objects.get(user=user)
            user_picture = social_ac.profile_pic_link

        except Exception as e:
            return HttpResponse("User Social Account not Found.")

        context = {
            "user_profile_img": user_picture,
            "user_email": user.email,
        }

        return render(request, "home.html", context=context)


def get_spreadsheet_id_by_name(spreadsheet_name, service):
    results = (
        service.files()
        .list(
            q=f"name='{spreadsheet_name}' and mimeType='application/vnd.google-apps.spreadsheet'",
            spaces="drive",
            fields="files(id, name)",
        )
        .execute()
    )

    items = results.get("files", [])
    if not items:
        print(f"No spreadsheets found with the name: {spreadsheet_name}")
        return None
    else:
        return items[0]["id"]


class ShowCalendarEvents(LoginRequiredMixin, View):

    def get_login_url(self):
        return reverse_lazy("launch_page")

    def get(self, request, *args, **kwargs):
        user = request.user
        show_event_logger.info(f'Request for user {user.email} to show calendar events has been initiated.')
        try:
            social_token = SocialToken.objects.get(user=user)
            user_picture = social_token.profile_pic_link
        except Exception as e:
            return HttpResponse("User Social Account not Found.")

        try:
            # Create credentials object
            credentials = Credentials(
                token=social_token.access_token,
                refresh_token=social_token.refresh_token,
                client_id=os.environ.get("GOOGLE_ACCOUNTS_CLIENT_ID"),
                client_secret=os.environ.get("GOOGLE_ACCOUNTS_CLIENT_SECRET"),
                token_uri="https://oauth2.googleapis.com/token",
            )

        except SocialToken.DoesNotExist:
            messages.error(request, "Error ! User is not Correctly Configured.")
            return redirect("home_page")
        
        response = requests.get(f"https://oauth2.googleapis.com/tokeninfo?access_token={credentials.token}")

        if response.status_code == 400:
            credentials.refresh(Request())
            print('token refreshed.')

            social_token = SocialToken.objects.get(user=user)
            social_token.access_token = credentials.token
            social_token.save()
            general_logger.info(f'Token for user {user.email} has been expired and refreshed.')

        drive_service = build("drive", "v3", credentials=credentials)

        spreadsheet_name = "planit_user_event"
        spreadsheet_id = get_spreadsheet_id_by_name(spreadsheet_name, drive_service)

        if spreadsheet_id:
            range_name = "Sheet1"
            service = build("sheets", "v4", credentials=credentials)
            result = (
                service.spreadsheets()
                .values()
                .get(spreadsheetId=spreadsheet_id, range=range_name)
                .execute()
            )
            rows = result.get("values", [])
        else:
            rows = []

        if rows:
            rows = rows[-1:0:-1]

        per_page = 5

        pgn = Paginator(rows, per_page)
        pgn_content = pgn.get_page(kwargs.get("page"))

        for event in pgn_content:
            event[4] = datetime.strptime(event[4], "%Y-%m-%dT%H:%M:%S")
            event[3] = datetime.strptime(event[3], "%Y-%m-%dT%H:%M:%S")

        context = {
            "user_profile_img": user_picture,
            "user_email": user.email,
            "page_content": pgn_content,
            "pages": range(1, pgn.num_pages + 1),
            "current_page": kwargs.get("page"),
        }
        show_event_logger.info(f'Saved Events for user {user.email} has been extracted successfully.')
        return render(request, "events.html", context)


def create_google_event_and_spreadsheet(
    user, credentials, event_title, event_description, event_start, event_end
):
    try:

        calendar_service = build("calendar", "v3", credentials=credentials)

        # Create the event on Google Calendar
        event = {
            "summary": event_title,
            "description": event_description,
            "start": {
                "dateTime": event_start,
                "timeZone": "Asia/Kolkata",
            },
            "end": {
                "dateTime": event_end,
                "timeZone": "Asia/Kolkata",
            },
        }
        created_event = (
            calendar_service.events().insert(calendarId="primary", body=event).execute()
        )

        # Initialize the Google Sheets API service
        gc = gspread.authorize(credentials)

        # Check if the spreadsheet exists, if not create it
        spreadsheet_title = "planit_user_event"
        spreadsheet = None
        try:
            spreadsheet = gc.open(spreadsheet_title)
        except gspread.SpreadsheetNotFound:
            spreadsheet = gc.create(spreadsheet_title)
            # Share the spreadsheet with the user
            worksheet.append_row(
                [
                    "Event ID",
                    "Event Title",
                    "Event Description",
                    "Event Start",
                    "Event End",
                ]
            )
            spreadsheet.share(
                created_event["id"], user.email, perm_type="user", role="writer"
            )

        # Select the first sheet
        worksheet = spreadsheet.sheet1

        # If the sheet is empty, set the headers
        if worksheet.row_count == 0:
            worksheet.append_row(
                [
                    "Event ID",
                    "Event Title",
                    "Event Description",
                    "Event Start",
                    "Event End",
                ]
            )

        # Append the event data
        worksheet.append_row(
            [
                created_event["id"],
                event_title,
                event_description,
                event_start,
                event_end,
            ]
        )

        return created_event["id"]

    except HttpError as error:
        print(f"An error occurred: {error}")
        return None


class CreateCalenderEvent(LoginRequiredMixin, View):

    def get_login_url(self):
        return redirect("launch_page")

    def post(self, request, *args, **kwargs):

        create_event_logger.info(f'User {request.user.email} sent a post request to create a new event.')
        event_title = request.POST.get("eventTitle")
        event_description = request.POST.get("eventDescription")
        event_start = request.POST.get("eventStart")
        event_end = request.POST.get("eventEnd")

        if not event_title:
            messages.error(request, "Event title is required.")
            return redirect("home_page")

        event_description = event_description if event_description else ""

        try:
            event_start_dt = datetime.strptime(event_start, "%Y-%m-%dT%H:%M")
            today_now = datetime.now().strptime(event_start, "%Y-%m-%dT%H:%M")

            if event_start_dt < today_now:
                messages.error(request, "Event start time cannot be in the past.")
                return redirect("home_page")

        except ValueError:
            messages.error(request, "Invalid format for event start time.")
            return redirect("home_page")

        try:
            event_end_dt = datetime.strptime(event_end, "%Y-%m-%dT%H:%M")
            if event_end_dt <= event_start_dt:
                messages.error(
                    request, "Event end time must be after event start time."
                )
                return redirect("home_page")

        except ValueError:
            messages.error(request, "Invalid format for event end time.")
            return redirect("home_page")

        user = request.user
        try:
            # Retrieve the Google social application and access token for the user
            social_token = SocialToken.objects.get(user=user)

            # Create credentials object
            credentials = Credentials(
                token=social_token.access_token,
                refresh_token=social_token.refresh_token,
                token_uri="https://oauth2.googleapis.com/token",
                client_id=os.environ.get("GOOGLE_ACCOUNTS_CLIENT_ID"),
                client_secret=os.environ.get("GOOGLE_ACCOUNTS_CLIENT_SECRET"),
            )

            response = requests.get(f"https://oauth2.googleapis.com/tokeninfo?access_token={credentials.token}")

            if response.status_code == 400:
                credentials.refresh(Request())
                print('token refreshed.')

                social_token = SocialToken.objects.get(user=user)
                social_token.access_token = credentials.token
                social_token.save()
                general_logger.info(f'Token for user {user.email} has been expired and refreshed.')

        except SocialToken.DoesNotExist:
            messages.error(request, "Error ! User is not Correctly Configured.")
            return redirect("home_page")

        results = create_google_event_and_spreadsheet(
            user,
            credentials,
            event_title,
            event_description,
            event_start_dt.isoformat(),
            event_end_dt.isoformat(),
        )

        if results:
            create_event_logger.info(f'Event {event_title} for {user.email} has been created and saved in google sheets.')
            messages.success(
                request, f"Calendar event {event_title} created sucessfully !"
            )
            return redirect("home_page")

        else:
            create_event_logger.error(f'Event {event_title} for {user.email} cananot be created.')
            messages.error(request, "Error! Event cannot be created successfully.")
            return redirect("home_page")
