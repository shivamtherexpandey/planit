from django.urls import path
from planitapp import views
from django.contrib.auth.views import LogoutView

urlpatterns = [
    path("", views.LoginPage.as_view(), name="launch_page"),
    path("planit/google/login", views.GoogleLogin.as_view(), name="google_login"),
    path("auth/google", views.GoogleAuth.as_view()),
    path("planit/google/logout", LogoutView.as_view(), name="google_logout"),
    path("planit/home", views.HomePage.as_view(), name="home_page"),
    path(
        "planit/calendar/event/show/<int:page>",
        views.ShowCalendarEvents.as_view(),
        name="list_events_page",
    ),
    path(
        "planit/calendar/event/create",
        views.CreateCalenderEvent.as_view(),
        name="create_event",
    ),
]
