from django.urls import path
from .views.auth import CreateToken, Login, Signup
from .views.user import MyProfile, SetPincode, UserFeedback, Tags, SendEmail, VerifyEmail
from .views.search import SearchNumber, SearchMultiNumber
from .views.util import GetState, GetCity, SetLang, SetLangImage, GetCountry
from .views.debug import RemoveAccount, EncryptData, DecryptData, Search

urlpatterns = [
    # Auth Routes
    path('auth/create_token', CreateToken().as_view(), name = 'CreateToken'),
    path('auth/signup', Signup.as_view(), name = 'Signup'),
    path('auth/login', Login.as_view(), name = 'Login'),

    # Search Routes
    path('search/by_number', SearchNumber.as_view(), name = 'SearchNumber'),
    path('search/multiNumber', SearchMultiNumber.as_view(), name = 'SearchMultiNumber'),

    # User Routes
    path('user/my_profile', MyProfile.as_view(), name = 'MyProfile'),
    # path('user/send_email/<str:email>/<str:mobile>', sendEmail.as_view(), name = 'sendEmail'),
    path('user/send_email', SendEmail.as_view(), name = 'SendEmail'),
    path('user/verify_email/<str:query>', VerifyEmail.as_view(), name = 'VerifyEmail'),
    path('user/set_pincode', SetPincode.as_view(), name = 'SetPincode'),
    path('user/tags', Tags.as_view(), name = 'Tags'),
    path('user/feedback', UserFeedback.as_view(), name = 'UserFeedback'),

    # Util Routes
    path('set_lang', SetLang.as_view(), name = 'SetLang'),
    path('set_lang_img', SetLangImage.as_view(), name = 'SearchLangImage'),
    path('get_state', GetState.as_view(), name = 'GetState'),
    path('get_city', GetCity.as_view(), name = 'GetCity'),
    path('get_country', GetCountry.as_view(), name = 'GetCountry'),

    # Testing APIs
    path('debug/encryptData', EncryptData.as_view(), name = 'EncryptData'),
    path('debug/decryptData', DecryptData.as_view(), name = 'DecryptData'),
    path('debug/removeAccount', RemoveAccount.as_view(), name = 'RemoveAccount'),
    path('debug/search', Search.as_view(), name = 'Search'),
]
