from django.conf.urls.defaults import *

urlpatterns = patterns('',
    # Example:
    # (r'^pyHealthVault/', include('pyHealthVault.foo.urls')),

    # Uncomment this for admin:
#     (r'^admin/', include('django.contrib.admin.urls')),
    (r'^$', 'pyHealthVault.webapp.views.index'),

    (r'^mvaultaction/$', 'pyHealthVault.webapp.views.mvaultaction'),

    (r'^mvaultentry/$', 'pyHealthVault.webapp.views.mvaultentry'),

)
