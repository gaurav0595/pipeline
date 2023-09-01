""" 
    Groups of URL Patterns
    @author: Govind Saini
    @updatedAt: 30th Nov'22
    @desc: URL groups for middleware authentication
"""

# Paths
signup = "/api/v1/auth/signup"
login = "/api/v1/auth/login"
search = "/api/v1/search/by_number"
multi_search = "/api/v1/search/multiNumber"
send_mail = "/api/v1/user/send_email"
profile = "/api/v1/user/my_profile"
pin = "/api/v1/user/set_pincode"
tags = "/api/v1/user/tags"
feedback = "/api/v1/user/feedback"
app_permission = "/api/v1/user/user_permission"
country = "/api/v1/get_country"
state = "/api/v1/get_state"
city = "/api/v1/get_city"
lang = "/api/v1/set_lang"

search_tc = "/api/v1/searchTC"

# URL-type Groups
auth_urls = [signup, login, search, send_mail, profile, pin, tags, feedback, app_permission, country, state, city, lang, multi_search, search_tc]
public_urls = [signup, login]
encrypted_urls = [signup, login, search, multi_search]


