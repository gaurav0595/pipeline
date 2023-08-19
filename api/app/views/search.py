import json,requests, environ

from rest_framework.views import APIView

from app.helper.logger import logger
from app.helper.commonFunction import get_error_response, forward_response, encrypt_data, decrypt_data, handle_exception, forward_exception

config = json.load(open('app/config/config.json'))

# read env
env = environ.Env()	
MINIO_BUCKET_URL = env('MINIO_BUCKET_URL')	
SEARCH_URL       = env('API_SEARCH_URL')	

# index/collections
SEARCH_INDEX   = config['data']['elastic']['indices']['search']
TAGS_INDEX     = config['data']['elastic']['indices']['tags']
APP_BUCKET     = config['data']['minio']['buckets']['app']
TAG_URL_PREFIX = MINIO_BUCKET_URL + APP_BUCKET + '/assets/tags/'
CALL_SEARCH_TYPES    = config['settings']['callSearchTypes']

# search any number (single number only)searchNumber
class SearchNumber(APIView):
    def post(self, request):
        try:
            # return get_error_response(500, 5001, "ruk jao yrrr, server down h, bola to tha !!!")
            cgk = request._userInfo['CGK']
            user_mobile = request._userInfo['mobile']

            if 'data' not in request.data or not isinstance(request.data['data'], str):
                logger.error("Encrypted data not found!")
                return get_error_response(400, 4002)

            req_data = request.data['data']
            req_data = json.loads(decrypt_data(req_data, cgk))

            if 'mobile' not in req_data or 'src' not in req_data:
                return get_error_response(400, 4002)

            search_mob = req_data['mobile']
            src = req_data['src']

            if src not in CALL_SEARCH_TYPES:
                return get_error_response(400, 4001, "Unknown source of search!")

            payload = {
                'searchNumber': search_mob,
                'userNumber': user_mobile,
                'src': src,
                'lang': request.headers.get('language') or 'en'
            }

            res = requests.post(SEARCH_URL + 'api/v1/micro/searchNumber', json=payload)

            status_code = res.status_code
            search_info = res.json()

            if 'data' in search_info and status_code == 200:
                search_info['data'] = encrypt_data(json.dumps(search_info['data']), cgk)

            return forward_response(status_code, search_info)
        except Exception as e:
            return handle_exception(forward_exception(e, 'searchNumber[view]'), request)


class SearchMultiNumber(APIView):
    def post(self, request):
        try:
            # return get_error_response(500, 5001, "ruk jao yrrr, server down h, bola to tha !!!")
            cgk = request._userInfo['CGK']
            user_mobile = request._userInfo['mobile']

            if 'data' not in request.data or not isinstance(request.data['data'], str):
                logger.error("Encrypted data not found!")
                return get_error_response(400, 4002)

            req_data = request.data['data']
            req_data = json.loads(decrypt_data(req_data, cgk))

            if 'mobile_list' not in req_data or 'src' not in req_data:
                return get_error_response(400, 4002)

            search_mobs = req_data['mobile_list']

            if type(search_mobs) is not list:
                return get_error_response(400, 4001)

            src = req_data['src']

            if src not in CALL_SEARCH_TYPES:
                return get_error_response(400, 4001, "Unknown source of search!")

            payload = {
                'searchNumbers': search_mobs,
                'userNumber': user_mobile,
                'src': src,
                'lang': request.headers.get('language') or 'en'
            }

            res = requests.post(SEARCH_URL + 'api/v1/micro/searchMultiNumber', json=payload)

            status_code = res.status_code
            search_info = res.json()
            if 'data' in search_info and status_code == 200:
                search_info['data'] = encrypt_data(json.dumps(search_info['data']), cgk)

            return forward_response(status_code, search_info)
        except Exception as e:
            return handle_exception(forward_exception(e, 'searchNumber[view]'), request)
