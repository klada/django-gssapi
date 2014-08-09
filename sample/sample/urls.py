from django.conf.urls import patterns, include, url

from django.contrib import admin
admin.autodiscover()

from . import views

urlpatterns = patterns('',
    # Examples:
    url(r'^$', views.home, name='home'),
    # url(r'^blog/', include('blog.urls')),

    url('^accounts/kerberos/', include('django_kerberos.urls')),
    url('^accounts/', include('django.contrib.auth.urls')),
    url(r'^admin/', include(admin.site.urls)),
)
