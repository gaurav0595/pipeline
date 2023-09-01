import json, requests, os
from rest_framework.views import APIView
import traceback
from app.helper.log_methods import Info, Error, Critical, Warn, SysLog
from app.model.elasticModel import es_search, es_delete_by_id
from app.helper.commonFunction import get_error_response, get_success_response, encrypt_data, decrypt_data, \
    handle_exception, forward_exception



M_ES_ENDPOINT_URL = os.environ.get('M_ES_ENDPOINT_URL')

config = json.load(open('app/config/config.json'))
USER_INDEX = config['data']['elastic']['indices']['users']

""" 
    Debug Views 
    @author: Govind Saini
    @updatedAt: 3rd Dec'22
    @desc: for interal debugging purposes
    @update: minor changes as whole project updated
"""


# To encrypt the Data
class EncryptData(APIView):
    def post(self, request):
        try:
            user_data = request.data
            enc_key = user_data['key']
            data_to_encrypt = user_data['data']
            if not isinstance(data_to_encrypt, str):
                data_to_encrypt = json.dumps(data_to_encrypt)

            enc = encrypt_data(data_to_encrypt, enc_key)
            return get_success_response(200, 2001, enc)
        except Exception as e:
            stack_trace = traceback.format_exc()
            Error('UNKNOWN_ERR', e.args[0], traceback=stack_trace)
            return handle_exception(forward_exception(e, 'encryptData[view]'), request)

class DecryptData(APIView):
    def post(self, request):
        try:
            user_data = request.data
            enc_key = user_data['key']
            data_to_decrypt = user_data['data']
            decrypted_data = decrypt_data(data_to_decrypt, enc_key)
            try:
                decrypted_data = json.loads(decrypted_data)
            except:
                pass

            return get_success_response(200, 2001, decrypted_data)
        except Exception as e:
            stack_trace = traceback.format_exc()
            Error('UNKNOWN_ERR', e.args[0], traceback=stack_trace)
            return handle_exception(forward_exception(e, 'decryptData[view]'), request)

class RemoveAccount(APIView):
    def post(self, request):
        try:
            testing_accounts = [
                "8209451539",  # Govind
                "7822064648",  # Govind
                "8971724494",  # Arpit Sir
                "9782222255",  # Ramesh sir
                "9587714529",  # Mohit
                "7503873087",  # Mayank
                "9013623264",  # Lokesh
                "8076364873",  # requested to add by mayank
                "9887105333",  # abhinav
                "7340470426" #prem
            ]

            if 'mobile' not in request.data:
                return get_error_response(400, 4003, "Please enter mobile!")

            mobile = str(request.data['mobile'])[-10:]
            if mobile not in testing_accounts:
                return get_error_response(400, 4001, "Not a valid testing account!")

            search_query = {"query": {"match": {"mobile": str(mobile)}}, "size": 1}
            user_res = es_search(USER_INDEX, search_query)

            if (not len(user_res)):
                return get_error_response(400, 4007)

            es_delete_by_id(USER_INDEX, user_res[0]['_id'])
            return get_success_response(200, 2001, mobile, "Account removed successfully!")
        except Exception as e:
            stack_trace = traceback.format_exc()
            Error('UNKNOWN_ERR', e.args[0], traceback=stack_trace)
            return handle_exception(forward_exception(e, 'removeAccount[view]'), request)


class Search(APIView):
    def post(self, request):
        try:
            payload = request.data
            method = payload.pop('method', None)
            action = payload.pop('action', None)

            if action is None or method is None:
                return get_error_response(400, 4001, "Please enter action and method!")

            url = f'{M_ES_ENDPOINT_URL}/{action}'
            headers = {'Content-Type': 'application/json'}
            response = requests.request(method, url, json=payload or None, headers=headers)
            results = response.json()
            return get_success_response(200, 2001, results)
        except Exception as e:
            return handle_exception(forward_exception(e, 'searchP[view]'), request)

