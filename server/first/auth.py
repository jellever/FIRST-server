# -------------------------------------------------------------------------------
#
#   FIRST Authentication module
#   Copyright (C) 2016  Angel M. Villegas
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License along
#   with this program; if not, write to the Free Software Foundation, Inc.,
#   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
#   Requirements
#   ------------
#   -   mongoengine
#
# -------------------------------------------------------------------------------

#   Python Modules
import re
import hashlib
import uuid
import time
import datetime
from functools import wraps

#   Django Modules
from django.http import HttpResponse, HttpRequest
from django.shortcuts import redirect
from django.urls import reverse

#   FIRST Modules
#   TODO: Use DBManager to get user objects and do User operations
from first.models import User
from first.error import FIRSTError

#   Thirdy Party
from mongoengine.queryset import DoesNotExist

BUILTIN_SERVICE = 'BUILTIN'


class FIRSTAuthError(FIRSTError):
    _type_name = 'FIRSTAuth'

    def __init__(self, message):
        super(FIRSTError, self).__init__(message)


def verify_api_key(api_key):
    users = User.objects(api_key=api_key)
    if not users:
        return None

    return users.get()


def require_apikey(view_function):
    @wraps(view_function)
    def decorated_function(*args, **kwargs):
        http401 = HttpResponse('Unauthorized', status=401)
        if 'api_key' not in kwargs:
            return http401

        key = kwargs['api_key'].lower()
        if key:
            user = verify_api_key(key)
            del kwargs['api_key']
            if user:
                kwargs['user'] = user
                return view_function(*args, **kwargs)

        return http401

    return decorated_function


def require_login(view_function):
    @wraps(view_function)
    def decorated_function(*args, **kwargs):
        request = None
        for arg in args:
            if isinstance(arg, HttpRequest):
                request = arg
                break

        if not request:
            return redirect(reverse('www:login'))

        auth = Authentication(request)
        if auth.is_logged_in:
            return view_function(*args, **kwargs)

        else:
            return redirect(reverse('www:login'))

    return decorated_function


class Authentication():
    def __init__(self, request):
        self.request = request
        if 'auth' not in request.session:
            request.session['auth'] = {}
        self.request.session['auth']['service'] = BUILTIN_SERVICE

    @property
    def is_logged_in(self):
        if (('auth' not in self.request.session) or ('expires' not in self.request.session['auth'])):
            return False

        expires = datetime.datetime.fromtimestamp(self.request.session['auth']['expires'])
        if expires < datetime.datetime.now():
            return False

        return True

    def login(self, url):
        handle = self.request.POST.get('handle')
        passwd = self.request.POST.get('creds')
        pass_hash = hashlib.sha256(passwd).hexdigest()
        try:
            user = User.objects.get(handle=handle, auth_data=pass_hash, service=BUILTIN_SERVICE)
        except DoesNotExist:
            user = None
        if not user:
            raise FIRSTAuthError('Login failed')
        self.request.session['info'] = {
            'name': user.name,
            'email': user.email
        }

        expire = datetime.datetime.now() + datetime.timedelta(days=1)
        self.request.session['auth']['expires'] = time.mktime(expire.timetuple())
        self.request.session['auth']['api_key'] = str(user.api_key)
        return redirect(url)

    def register_user(self):
        request = self.request
        required = ['handle', 'creds', 'email']
        if False in [x in request.POST for x in required]:
            return HttpResponse('Error: Missing fields!')

        user = None
        handle = request.POST['handle']
        service = BUILTIN_SERVICE
        name = request.POST['handle']
        email = request.POST['email']
        credentials = hashlib.sha256(request.POST['creds']).hexdigest()

        if len(request.POST['creds']) < 8:
            raise FIRSTAuthError('Password must be >= 8 characters')
        if not re.match('^[A-Za-z_\d]+$', handle):
            return FIRSTAuthError('Invalid handle')

        api_key = uuid.uuid4()

        try:
            user = User.objects.get(handle=handle)
            raise FIRSTAuthError('User already exists!')
        except DoesNotExist:
            user = User(name=name,
                        api_key=api_key,
                        email=email,
                        handle=handle,
                        number=0,
                        service=service,
                        auth_data=credentials)

            user.save()
            return redirect(reverse('www:index'), _anchor='login')

        raise FIRSTAuthError('Unable to register user')

    @staticmethod
    def get_user_data(email):
        try:
            user = User.objects.get(email=email)
            return user

        except DoesNotExist:
            return None
