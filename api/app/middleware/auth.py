import json, jwt, environ
from app.helper.commonFunction import get_error_response, decrypt_data, handle_exception
from app.helper.logger import logger
from app.model.elasticModel import es_count, es_search
from django.utils.deprecation import MiddlewareMixin
from .url_info import auth_urls, encrypted_urls, public_urls


# GET ENV variables
env = environ.Env()
JWT_SECRET_KEY = env('JWT_SECRET_KEY') 

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
                        logger.info(f"{mobile}: {request_path}")

                        # GET CGK for encrypted routes
                        if request_path in encrypted_urls:
                            CGK = decrypt_data(userInfo['ck'], 'SPK')
                            userInfo['CGK'] = CGK

                        # Validate if it's an active user
                        if request_path in public_urls:
                            if userInfo['userType'] != "guest":
                                logger.error("User Token for Public URL!")
                                return get_error_response(401, 4011, 'Log-out first to register again!')
                        else:
                            if userInfo['userType'] == "guest":
                                logger.error("Please register first!")
                                return get_error_response(401, 4011, 'Please register first!')

                            
                            count_query = {"query": {"match": {"mobile": mobile}}, "size": 1}
                            active_user = es_search(USER_INDEX, count_query)
                            if not active_user:
                                logger.error("User Not Exists!")
                                return get_error_response(400, 4007)
                            else:
                                userInfo['record'] = active_user[0]
                        request._userInfo = userInfo
                    except jwt.ExpiredSignatureError:
                        raise Exception('TOKEN_ERR', {'subcode': 4013})
                    except (jwt.DecodeError, jwt.InvalidTokenError):
                        raise Exception('TOKEN_ERR', {'subcode': 4012})
                else:
                    raise Exception('TOKEN_ERR', {'subcode': 4011})
        except Exception as e:
            return handle_exception(e, request)
        
        
