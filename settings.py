import os

#pyHealthVault library and webapp settings - keys, appids, emplates etc
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

TEMPLATE_DIRS = (
    # Put strings here, like "/home/html/django_templates" or "C:/www/django/templates".
    # Always use forward slashes, even on Windows.
    # Don't forget to use absolute paths, not relative paths.
    BASE_DIR+'/webapp' 
)

HV_APPID 	 = 'bafb1313-d4e0-421c-b3b5-4e3a55639c19'
HV_SHELL_URL	 = 'https://account.healthvault-ppe.com'

HV_SERVICE_SERVER  = 'platform.healthvault-ppe.com'

APP_ACTION_URL   = 'http%3A//localhost%3A8080/mvaultaction'

APP_PUBLIC_KEY = """0x\
009f8e3748b82926fe0443d980a9ca\
9d3d5470fc9a3234005ae75f665ada\
d86724aa0a357c44a57049848a4ba1\
acef066f938f71627e63d7eda19783\
1034e9da3d081d45d96834fb24a83b\
ef90a7a19609560575e1917b6ccf40\
ca553703c0e6500443b08fb0e04c76\
2963a227bdb936ef96fb59c15bc941\
a7e6a306337a3ba62f3753b6dfb367\
dbf26bb7840723fb28257b56fe3eee\
6c4136bd38d03f6d1d263ac973036a\
4f9ccd28db3c206c2d5a56be079138\
0c16a4bb70e7d6f0c5b2a2eb4d9119\
acf7f6af51ca349a189f2b93279379\
6755856b2a84645b4bed300fa9de8a\
35c22347210ebd3fd7f60eb0a329e8\
8e41989699c7f4dec8268028082b46\
33a7"""
 
APP_PRIVATE_KEY = """0x\
00955b675ce7277e9ca219716d0383\
eb15120a822b457b7029a814a197c2\
ec7800d63ba03da774c65bcb7a39ba\
2a4bc5d68466ee58a8bf85cda84a50\
21c7a670e858c42e32895daf0a6d81\
4d8c379f06f7ce52663ab518b88e79\
b3ed7906467851c6ec26471be79b2b\
b12ad70c248950678f09d2c731c87f\
715070a2c9654e990c77784f140c14\
bff26e999ea93db26f86a3944470de\
72a4620465c0451971992a9a520186\
5aab92b3d199613d011d68d5f32b1c\
ac0fd6ce05aa7e5660e4e528bc7f89\
2e17c09ce1571176333d84a68f90e5\
a60ce8f62177cc7d19017d00ada933\
00933d3e0105107d4dbeab73e09302\
e80458d3d316430f61ca7bea28b2aa\
5ce1"""

APP_THUMBPRINT = '4ca512b0b5a5ca3e751e6f92f7a1c1e5ebb0309c'

# Django settings for pyHealthVault project.
DEBUG = True
TEMPLATE_DEBUG = DEBUG

ADMINS = (
    # ('Your Name', 'your_email@domain.com'),
)

MANAGERS = ADMINS

DATABASE_ENGINE = ''           # 'postgresql_psycopg2', 'postgresql', 'mysql', 'sqlite3' or 'oracle'.
DATABASE_NAME = ''             # Or path to database file if using sqlite3.
DATABASE_USER = ''             # Not used with sqlite3.
DATABASE_PASSWORD = ''         # Not used with sqlite3.
DATABASE_HOST = ''             # Set to empty string for localhost. Not used with sqlite3.
DATABASE_PORT = ''             # Set to empty string for default. Not used with sqlite3.

# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# If running in a Windows environment this must be set to the same as your
# system time zone.
TIME_ZONE = 'America/Chicago'

# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
LANGUAGE_CODE = 'en-us'

SITE_ID = 1

# If you set this to False, Django will make some optimizations so as not
# to load the internationalization machinery.
USE_I18N = True

# Absolute path to the directory that holds media.
# Example: "/home/media/media.lawrence.com/"
MEDIA_ROOT = ''

# URL that handles the media served from MEDIA_ROOT. Make sure to use a
# trailing slash if there is a path component (optional in other cases).
# Examples: "http://media.lawrence.com", "http://example.com/media/"
MEDIA_URL = ''

# URL prefix for admin media -- CSS, JavaScript and images. Make sure to use a
# trailing slash.
# Examples: "http://foo.com/media/", "/media/".
ADMIN_MEDIA_PREFIX = '/media/'

# Make this unique, and don't share it with anybody.
SECRET_KEY = 'xr--(48l1whu9keemewf@9j(og2i$3+ty9m%&97o6xkw1g$a#d'

# List of callables that know how to import templates from various sources.
TEMPLATE_LOADERS = (
    'django.template.loaders.filesystem.load_template_source',
    'django.template.loaders.app_directories.load_template_source',
#     'django.template.loaders.eggs.load_template_source',
)

MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.middleware.doc.XViewMiddleware',
)

ROOT_URLCONF = 'pyHealthVault.urls'


INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
)
