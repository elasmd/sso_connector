import logging
from json import JSONDecodeError

import requests
from django.conf import settings
from django.utils import timezone
from drf_util.models import User
from drf_util.utils import join_url, gt
from rest_framework import status
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response

logger = logging.getLogger(__name__)

SSO_HEADER = "Bearer"
SSO_DOMAIN = settings.SSO_DOMAIN

# SSO_DOMAIN = 'http://127.0.0.1:8000'
AUTH_PATH_SITE = join_url(SSO_DOMAIN, "authorization/token/service/verify/")
PASS_PATH_SITE = join_url(SSO_DOMAIN, "account/user/")
LOGIN_PATH_SITE = join_url(SSO_DOMAIN, "authorization/token/")
CREATE_PATH_SITE = join_url(SSO_DOMAIN, "authorization/user/create/")
MIGRATE_PATH_SITE = join_url(SSO_DOMAIN, "authorization/user/migrate/")
RESTORE_PATH_SITE = join_url(SSO_DOMAIN, "authorization/user/restore/")
CONFIRM_RESTORE_PATH_SITE = join_url(SSO_DOMAIN, "account/confirm-restore/")


def get_token(request):
    authorization = request.META.get('HTTP_AUTHORIZATION', "")
    if authorization.startswith('Token'):
        return authorization.split(" ")[-1]


def get_sso_response(url, function_method, data={}, headers={}):
    try:
        request = function_method(url, json=data, headers=headers)
        response = Response(request.json(), status=request.status_code)
    except (requests.exceptions.RequestException, JSONDecodeError):
        logger.warning("Response error from: %s", url)
        response = Response({"detail": "SSO error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    return response


def get_sso_user(request):
    data = {}
    token = get_token(request)
    if token:
        response = get_sso_response(AUTH_PATH_SITE, requests.post,
                                    {"token": token, "service_token": settings.AUTH_SERVICE_TOKEN},
                                    headers={"Accept-Language": request.LANGUAGE_CODE})
        if response.status_code == status.HTTP_200_OK:
            data = response.data
        elif response.status_code == status.HTTP_401_UNAUTHORIZED:
            raise AuthenticationFailed()

    return data


def change_password(request, data):
    token = get_token(request)
    response = get_sso_response(PASS_PATH_SITE, requests.patch, data,
                                {"Authorization": "%s %s" % (SSO_HEADER, token),
                                 "Accept-Language": request.LANGUAGE_CODE})
    return response


def sso_login(username, password, lang=settings.DEFAULT_LANG):
    response = get_sso_response(LOGIN_PATH_SITE, requests.post,
                                {"username": username, "password": password,
                                 "service_token": settings.AUTH_SERVICE_TOKEN},
                                headers={"Accept-Language": lang})
    if response.status_code == status.HTTP_200_OK:
        if not User.objects.filter(username=username).exists():
            # if profile closed
            logger.warning("Profile closed")
            response.status_code = status.HTTP_400_BAD_REQUEST
            response.data = {"non_field_errors": ["User profile blocked"]}
    return response


def create_sso_user(lang=settings.DEFAULT_LANG, **kwargs):
    kwargs["service_token"] = settings.AUTH_SERVICE_TOKEN
    response = get_sso_response(CREATE_PATH_SITE, requests.post, kwargs, headers={"Accept-Language": lang})
    return response


def confirm_restore_sso_user(lang=settings.DEFAULT_LANG, **kwargs):
    kwargs["service_token"] = settings.AUTH_SERVICE_TOKEN
    response = get_sso_response(CONFIRM_RESTORE_PATH_SITE, requests.post, kwargs, headers={"Accept-Language": lang})
    return response


def restore_sso_user(lang=settings.DEFAULT_LANG, **kwargs):
    kwargs["service_token"] = settings.AUTH_SERVICE_TOKEN
    response = get_sso_response(RESTORE_PATH_SITE, requests.post, kwargs, headers={"Accept-Language": lang})
    return response


def migrate_sso_user(lang=settings.DEFAULT_LANG, **kwargs):
    kwargs["service_token"] = settings.AUTH_SERVICE_TOKEN
    response = get_sso_response(MIGRATE_PATH_SITE, requests.post, kwargs, headers={"Accept-Language": lang})
    return response


class ExternalAuthBackend(BaseAuthentication):
    def authenticate(self, request, **kwargs):
        user = ExternalAuthBackend.get_user(request)
        return (user, None) if user else None

    @staticmethod
    def get_user(request):
        data_response = get_sso_user(request)
        if data_response and data_response.get("username"):
            email = data_response.get("email")
            user, _ = User.objects.get_or_create_user(username=data_response.get("username"))
            if not user.email and email:
                user.email = email
                user.save()
            # Needed for informer user model
            # if gt(user, "useraccount"):
            #     if not user.useraccount.is_approved:
            #         return None
            # else:
            #     user.useraccount = UserAccount.objects.create(user_id=user.id)
            # user.useraccount.last_activity = timezone.now()
            # user.useraccount.save()
            return user
        return None

    def authenticate_header(self, request):
        return "Not found"
