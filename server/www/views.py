#   Django Modules
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.urls import reverse
from django.views.decorators.http import require_GET, require_POST


#   FIRST Modules
from www.models import Function, User
from first.auth import Authentication, require_login, FIRSTAuthError


def handler404(request):
    return render(request, 'www/404.html', None)


def index(request):
    data = {'title': 'Home',
            'user_num': User.objects.count(),
            'function_num': Function.objects.count(),
            'register_html': True,
            'login_html': True,
            }
    return render(request, 'www/index.html', data)


@require_login
def profile(request):
    '''
    Should show the user's name, email, ranking and API key
    '''
    if 'info' not in request.session:
        return redirect(reverse('www:login'))

    info = request.session['info']
    user = Authentication.get_user_data(info['email'])

    if not user:
        return redirect(reverse('www:index'))

    count = Function.objects(metadata__user=user).count()
    data = {'title': 'Profile',
            'user': user.dump(True),
            'metadata_count': count}
    return render(request, 'www/profile.html', data)


def logout(request):
    request.session.flush()
    return HttpResponse('Logout')


@require_POST
def login(request):

    #   Check for errors
    # +++++++++++++++++++

    auth = Authentication(request)
    if auth.is_logged_in:
        return redirect('www:profile')

    request.session['redirect'] = 'www:profile'

    try:
        return auth.login('www:profile')

    except FIRSTAuthError as e:
        return HttpResponse(('Error: {}<br /><a href="/#login">Try logging '
                            'in again</a>').format(e))


@require_GET
def oauth(request, service):
    try:
        uri = 'www:profile'
        if 'redirect' in request.session:
            uri = request.session['redirect']
            del request.session['redirect']

        logging_in = uri == 'www:profile'
        if request.GET.get('code'):
            auth_code = request.GET['code']

            auth = Authentication(request)
            return auth.login_step_2(auth_code, reverse(uri), logging_in)

    except FIRSTAuthError as e:
        if 'registered' in str(e):
            return HttpResponse(('Error: {}<br /><a href="/">Register to use '
                                'FIRST</a>').format(e))

        return HttpResponse(('Error: {}<br /><a href="/">Try logging in '
                            'again</a>').format(e))

    except RuntimeError as e:
        return redirect('www:profile')

    return redirect('www:index')


@require_POST
def register(request):
    '''
    Required: handle
    Get name and email from sign in service
    '''

    #   Check for errors
    # +++++++++++++++++++
    if 'error' in request.GET:
        return HttpResponse('Access Denied')

    auth = Authentication(request)
    if request.method == 'POST':
        return auth.register_user()
