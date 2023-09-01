import json, jwt, os
from app.helper.commonFunction import get_error_response, decrypt_data, handle_exception
from app.model.elasticModel import es_count, es_search
from django.utils.deprecation import MiddlewareMixin
from .url_info import auth_urls, encrypted_urls, public_urls
from app.helper.log_methods import Info, Error, Critical, Warn
import traceback

# GET ENV variables
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')

config = json.load(open('app/config/config.json'))
err_codes = json.load(open('app/config/custom_err_codes.json'))
ES_INDICES       = config['data']['elastic']['indices']
USER_INDEX       = ES_INDICES['users']

""" 
    Auth Middleware
    @author: Govind Saini
    @updatedAt: 8th Dec'22
    @desc: checks for valid jwt, user and decodes some data for views
    @update: updated exception handling
"""

class AuthMiddleware(MiddlewareMixin):
    def process_request(self, request):
        try:
            request_path = request.path

            # Validate JWT Token
            if request_path in auth_urls:
                jwt_token = request.headers.get('Token', None)
                if jwt_token:
                    try:
                        # Decode JWT Token
                        userInfo = jwt.decode(jwt_token, JWT_SECRET_KEY, algorithms=['HS256'])
                        mobile = userInfo['mobile']

                        Info('LOG', f'On decoding token got user details: {mobile}: {request_path}')

                        # GET CGK for encrypted routes
                        if request_path in encrypted_urls:
                            CGK = decrypt_data(userInfo['ck'], 'SPK')
                            userInfo['CGK'] = CGK

                        # Validate if it's an active user
                        if request_path in public_urls:
                            if userInfo['userType'] != "guest":
                                Error('TOKEN_ERR', 'Log-out first to register again!')
                                return get_error_response(401, 4011, 'Log-out first to register again!')
                        else:
                            if userInfo['userType'] == "guest":
                                Error('TOKEN_ERR', "Please register first!")
                                return get_error_response(401, 4011, 'Please register first!')

                            
                            count_query = {"query": {"match": {"mobile": mobile}}, "size": 1}
                            active_user = es_search(USER_INDEX, count_query)
                            if not active_user:
                                Error('TOKEN_ERR', "User Not Exists!")
                                return get_error_response(400, 4007)
                            else:
                                userInfo['record'] = active_user[0]
                        request._userInfo = userInfo
                    except jwt.ExpiredSignatureError:
                        Error('TOKEN_ERR', "Token Expired!")
                        raise Exception('TOKEN_ERR', {'subcode': 4013})
                    except (jwt.DecodeError, jwt.InvalidTokenError):
                        Error('TOKEN_ERR', "Invalid token")
                        raise Exception('TOKEN_ERR', {'subcode': 4012})
                else:
                    Error('TOKEN_ERR', "Token not found")
                    raise Exception('TOKEN_ERR', {'subcode': 4011})
        except Exception as e:
            stack_trace = traceback.format_exc()
            Error('TOKEN_ERR', e.name, traceback=stack_trace)
            return handle_exception(e, request)
        
        
