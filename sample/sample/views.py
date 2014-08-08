from django.contrib.auth.decorators import login_required
from django import http


@login_required
def home(request):
    return http.HttpResponse(u'It worked ' + request.user.username + u'!', content_type='text/plain')
