import json
import math
import re
from datetime import datetime
from rest_framework.views import APIView
from operator import itemgetter
from app.model.elasticModel import es_search, es_update_by_id, es_insert, es_count, es_delete_by_id
from app.helper.commonFunction import (
otpgen,
originate_call,
otp_call,
get_error_response,
send_sms,
get_success_response,
validate_mob,
generate_token,
encrypt_data,
decrypt_data,
gen_hash_mob_code,
get_time_stamp as get_ts,
get_iso_date,
handle_exception,
forward_exception,
gen_user_id
)
from app.helper.logger import logger

config = json.load(open('app/config/config.json'))
err_codes = json.load(open('app/config/custom_err_codes.json'))

# Configs
ES_INDICES       = config['data']['elastic']['indices']
USER_LOGS_INDEX  = ES_INDICES['user_logs']
SEARCH_INDEX     = ES_INDICES['search']
USER_INDEX       = ES_INDICES['users']
OTP_INDEX        = ES_INDICES['otp']

USER_BLOCK_TIME  = config['settings']['userBlockTime'] # in mins
WRONG_OTP_LIMIT  = config['settings']['wrongOTPLimit']
RESEND_OTP_LIMIT = config['settings']['resendOTPLimit']
OTP_TIME_LIMIT   = config['settings']['OTPTimeLimit']
SIGNUP_TTL       = config['settings']['signupTTL']
methodList       = config['settings']['methodList']
SenderMobile     = config['services']['send_sms']['sender']


Pattern = re.compile("^123456789[0-9]{1}$")


"""
    Auth Views 
    @author: Govind Saini
    @updatedAt: 22nd Dec'22
    @desc: user registration handling
    @update: update verified in caller when a user successfully registers
    @removed: mobile from /signup & /login body
"""

class CreateToken(APIView):
    def get(self, request):
        try:
            if "ck" not in request.headers or "mobile" not in request.headers:
                raise Exception("INVALID_HEADERS")

            ck = request.headers["ck"]
            mobile = request.headers["mobile"]
            payload = {}

            if Pattern.match(mobile):
                logger.info(mobile)
                payload["testingAccount"] = "testingAccount"
            else:
                mobRes = validate_mob(mobile)
                if not mobRes:
                    raise Exception("INVALID_REQUEST", {"subcode": 4003})
                mobile = mobile[-10:]

            if len(ck) == 0:
                raise Exception("INVALID_HEADERS")

            # Decrypt CGK key using Default AES Key
            CGK = decrypt_data(ck, "DAK")

            # # Encrypt CGK with Server Private key
            spk_encrypted_cgk = encrypt_data(CGK, "SPK")
            currentTs = get_ts()

            payload["userType"] = "guest"
            payload["mobile"] = mobile
            payload["ck"] = spk_encrypted_cgk
            payload["loginStatus"] = 0
            payload["createdAt"] = currentTs
            payload["exp"] = currentTs + 600  # 10 mins

            logger.info(payload)
            data = generate_token(payload)["data"]
            return get_success_response(200, 2001, data)

        except Exception as e:
            return handle_exception(forward_exception(e, "CreateToken[view]"), request)
# common function for Login and SignUp
def find_signup_log(mobile, method, vrf_status=0):
    try:
        range_time = get_ts() - SIGNUP_TTL * 60  # 30 mins before (30*60)
        query = {
            "size": 1,
            "query": {
                "bool": {
                    "must": [
                        {"match": {"mobile": mobile}},
                        {"range": {"date": {"gte": range_time}}},
                        {"match": {"vrf": vrf_status}},
                        {"match": {"method": method}}
                    ]
                }
            },
            "sort": [{"date": {"order": "desc"}}]
        }

        search_result = es_search(USER_LOGS_INDEX, query)
        return search_result
    except Exception as e:
        raise forward_exception(e, 'find_signup_log')



class Signup(APIView):
    def find_otp_log(self, mobile):
        try:
            ts_range = get_ts() - OTP_TIME_LIMIT * 60
            count_query = {
                "query": {
                    "bool": {
                        "must": [
                            {"match": {"mobile": str(mobile)}},
                            {"range": {"creation_time": {"gte": ts_range}}}
                        ]
                    }
                },
                "sort": [{"creation_time": "desc"}],
                "size": 1,
            }

            result = es_search(OTP_INDEX, count_query)
            return result[0] if len(result) > 0 else None
        except Exception as e:
            raise forward_exception(e, 'find_otp')

    def insert_otp_log(self, mobile):
        try:

            if Pattern.match(mobile):
                otp = "666666"
            else:
                otp = otpgen()

            insert_obj = {
                "OTP": otp,
                "creation_time": get_ts(),
                "retry_count": 0,
                "mobile": mobile,
                "wrong_count": 0
            }

            es_insert(OTP_INDEX, insert_obj)
            return otp
        except Exception as e:
            raise forward_exception(e, 'insert_otp_log')

    def create_signup_request(self, request, mobile, method, enc_key=None, set_obj=None):
        if set_obj is None:
            set_obj = {}
        try:
            # Check if an existing recent request is available.
            log_info = find_signup_log(mobile, method)

            update_res = None
            if len(log_info) > 0:
                # Update existing log.
                log_info = log_info[0]
                log_id = log_info['_id']

                if log_info.get("retry_count") is None:
                    set_obj['retry_count'] = 1
                else:
                    set_obj['retry_count'] = log_info['retry_count'] + 1

                update_res = es_update_by_id(USER_LOGS_INDEX, log_id, set_obj)
            else:
                # Insert fresh log for signup request.
                insert_obj = {
                    'mobile': mobile,
                    "method": method,
                    "vrf": 0,
                    'date': get_ts()
                }
                insert_obj.update(set_obj)

                insert_res = es_insert(USER_LOGS_INDEX, insert_obj)
                if insert_res == "created":
                    update_res = True

            # Send response to user.
            if update_res:
                encrypted_data = None
                if method == "FC" or method == "SS":
                    if method == "FC":
                        set_obj['caller_id'] = set_obj['caller_id'][1:-5]
                        del set_obj['caller_id']
                    else:
                        set_obj['sender_id'] = set_obj['senderId']
                        del set_obj['senderId']
                    encrypted_data = encrypt_data(json.dumps(set_obj), enc_key)

                return get_success_response(200, 2001, encrypted_data)
            else:
                raise Exception('Unable to update signup log!')
        except Exception as e:
            return handle_exception(forward_exception(e, 'SignUp-CSR[view]'), request)

    def send_otp(self, request, mobile, method, otp):
        if method == "SO":
            send_sms(mobile, otp)
            # send_sms_SMPP(mobile, otp, logger)
        else:
            otp_call(mobile, otp)

        return self.create_signup_request(request, mobile, method)

    def post(self, request):
        try:
            mobile = request._userInfo['mobile']
            CGK = request._userInfo['CGK']
            
            # if 'testingAccount' in request._userInfo:
            #     testingAccount = request._userInfo['testingAccount']
            #     logger.info(testingAccount)
            #     logger.info(mobile)


            # req validations
            if 'data' not in request.data or not isinstance(request.data['data'], str):
                logger.error("Encrypted data not found")
                return get_error_response(400, 4002)

            req_data = json.loads(decrypt_data(request.data['data'], CGK))
            if('method' not in req_data): 
                return get_error_response(400, 4002)

            method = req_data['method']
            if method not in methodList:
                logger.error("Invalid Method!!")
                return get_error_response(400, 4005)

            if 'testingAccount' in request._userInfo and method != "SO":
                logger.error("Invalid Method!!")
                return get_error_response(400, 4005)
                # testingAccount = request._userInfo['testingAccount']
                # logger.info(testingAccount)
                # logger.info(mobile)

            # handle signup methods
            if(method == "FC"):
                raise Exception('code fat go!')
                """ Handle Signup via FC """
                call_resp = originate_call(mobile)

                if(not call_resp):
                    logger.error("Unable to originate call!")
                    return get_error_response(500, 5001)

                call_resp = json.loads(call_resp)
                caller_id = call_resp['connected']['number']
                set_obj = { 'caller_id' : caller_id }
                return self.create_signup_request(mobile, method, CGK, set_obj)

            elif(method == "SS"):
                """ Handle Signup via SS """
                hashMobCode = gen_hash_mob_code(mobile)
                set_obj = {
                    'senderId': SenderMobile,
                    'message': hashMobCode
                }
                return self.create_signup_request(request, mobile, method, CGK, set_obj)

            elif(method == "CO" or method == "SO"):
                """ Handle Signup via SO/CO """
                otp_log = self.find_otp_log(mobile)

                if not otp_log:
                    otp = self.insert_otp_log(mobile)
                    return self.send_otp(request, mobile, method, otp)
                else:
                    if(otp_log.get("block_time") is None):
                        otp = otp_log['OTP']
                        retry_count = otp_log['retry_count']
                        last_req_ts = otp_log['updation_time'] if otp_log.get("updation_time") is not None else otp_log['creation_time']
                        time_diff = math.floor((get_ts() - last_req_ts) / 60) # time diff in mins

                        if(time_diff >= SIGNUP_TTL or retry_count >= RESEND_OTP_LIMIT):
                            # re-generate otp
                            otp = otpgen()
                            set_obj = { "OTP": otp, "updation_time": get_ts(), "retry_count": 0 }
                            es_update_by_id(OTP_INDEX, otp_log['_id'], set_obj)
                        else:
                            inc_script = { "source": "ctx._source.retry_count++;" }
                            es_update_by_id(OTP_INDEX, otp_log['_id'], script = inc_script)

                        # Resend OTP
                        return self.send_otp(request, mobile, method, otp)
                    else:
                        # send error msg with how much time left in re-req
                        time_diff = USER_BLOCK_TIME - math.floor((get_ts() - otp_log['block_time']) / 60) # in mins
                        return get_error_response(403, 4031, { 'msg': f"{time_diff} minutes are left to unblock"})
        except Exception as e:
            return handle_exception(forward_exception(e, 'SignUp[view]'), request)


class Login(APIView):
    def update_user_as_verified(self, mobile):
        if Pattern.match(mobile):
            return
        m_index = SEARCH_INDEX.get(str(mobile[0]))
        query = {
            "size": 1,
            "query": {
                "bool": {
                    "must": [{"match": {"mobile": mobile}}]
                }
            }
        }
        search_result = es_search(m_index, query)

        # hit db update query only if needed
        if len(search_result):
            caller_info = search_result[0]
            user_id = caller_info['_id']
            user_status = caller_info['user_type'] if caller_info.get('user_type') else []

            if 'verified' not in user_status:
                user_status.append('verified')
                es_update_by_id(m_index, user_id, {'user_type': user_status})

    def create_login_request(self, request, mobile, method, jwt_client_key, caller_id=None, otp_id=None):
        try:
            vrf_status = 1 if method == 'SS' else 0
            log_info = find_signup_log(mobile, method, vrf_status)

            if len(log_info):
                log_id = log_info[0]['_id']

                # check if same caller_id for FC
                if method == 'FC' and log_info[0]['caller_id'][-10:] != str(caller_id):
                    logger.error("Invalid caller_id!")
                    return get_error_response(400, 40015)

                update_obj = {'login': 1, 'vrf': 1}
                log_resp = es_update_by_id(USER_LOGS_INDEX, log_id, update_obj)

                if log_resp:
                    user_query = {"query": {"match": {"mobile": str(mobile)}}, "size": 1}
                    user_res = es_search(USER_INDEX, user_query)
                    user_info = {'login_type': method, 'last_login': get_ts()}

                    if len(user_res):
                        if user_res[0].get('user_id'):
                            user_id = user_res[0]['user_id']
                        else:
                            user_id = gen_user_id()
                            user_info['user_id'] = user_id

                        es_update_by_id(USER_INDEX, user_res[0]['_id'], user_info)
                    else:
                        user_id = gen_user_id()
                        user_info.update({'user_id': user_id, 'mobile': mobile, 'created_dt': get_ts()})
                        es_insert(USER_INDEX, user_info)

                    # if SO/CO delete otp record before serving response
                    if method == 'SO' or method == 'CO':
                        es_delete_by_id(OTP_INDEX, otp_id)

                    payload = {
                        "mobile": mobile,
                        "ck": jwt_client_key,
                        "loginStatus": 1,
                        "userType": "verified",
                        "createdAt": get_ts(),
                        "user_id": user_id
                    }

                    data = generate_token(payload)['data']
                    self.update_user_as_verified(mobile)
                    return get_success_response(200, 2002, data)
                else:
                    logger.error("Unable to update user log!")
                    return get_error_response(500, 5002)
            else:
                if method == 'SS':
                    logger.error("Unable to validate message!")
                    return get_error_response(404, 4041, "Unable to validate message!")
                else:
                    logger.error("No Logs Found for the User")
                    return get_error_response(404, 4041)
        except Exception as e:
            return handle_exception(forward_exception(e, 'Login-CSR[view]'), request)

    def validate_otp(self, request, jwt_client_key, mobile, method, otp):
        try:
            ts_range = get_ts() - OTP_TIME_LIMIT * 60
            otp_query = {
                "query": {
                    "bool": {
                        "must": [
                            {"match": {"mobile": str(mobile)}},
                            {"range": {"creation_time": {"gte": ts_range}}}
                        ]
                    }
                },
                "sort": [{"creation_time": "desc"}],
                "size": 1,
            }

            otp_details = es_search(OTP_INDEX, otp_query)
            if len(otp_details):
                otp_id, actual_otp, wrong_count = itemgetter('_id', 'OTP', 'wrong_count')(otp_details[0])

                # when a user inputs wrong OTP 3 times
                if otp_details[0].get('block_time'):
                    time_diff = USER_BLOCK_TIME - math.floor((get_ts() - otp_details[0]['block_time']) / 60)  # in mins
                    block_msg = f'{time_diff} minutes are left to unblock'
                    logger.info(block_msg)
                    return get_error_response(403, 4031, block_msg)

                # check if user OTP is equal to DB(Stored) OTP
                if str(otp) == str(actual_otp):
                    return self.create_login_request(request, mobile, method, jwt_client_key, otp_id=otp_id)
                else:
                    update_script = {
                        "source": "ctx._source.wrong_count++;",
                        "lang": "painless",
                        "params": {
                            "block_time": get_ts()
                        }
                    }
                    if wrong_count + 1 == WRONG_OTP_LIMIT:
                        update_script['source'] += "ctx._source.block_time = params.block_time"

                    es_update_by_id(OTP_INDEX, otp_id, script=update_script)

                    logger.error("Invalid OTP!")
                    return get_error_response(400, 4004)
            else:
                logger.error("OTP Not Exists/requested!!")
                return get_error_response(500, 5001)

        except Exception as e:
            raise forward_exception(e, 'validate_otp')

    def post(self, request):
        try:
            mobile = request._userInfo['mobile']
            jwt_client_key = request._userInfo['ck']
            CGK = request._userInfo['CGK']

            # Request validations
            if 'data' not in request.data or not isinstance(request.data['data'], str):
                logger.error("Encrypted data not found!")
                return get_error_response(400, 4002)

            req_data = json.loads(decrypt_data(request.data['data'], CGK))

            if 'method' not in req_data:
                return get_error_response(400, 4002)

            method = req_data['method']
            if method not in methodList:
                logger.error("Invalid Method")
                return get_error_response(400, 4005)

            # Handle signup verification
            """ Handle SS and FC """
            if method == 'FC':
                if 'caller_id' not in req_data:
                    return get_error_response(400, 4002, 'caller_id not found!')
                return self.create_login_request(request, mobile, method, jwt_client_key, req_data['caller_id'])

            if method == 'SS':
                return self.create_login_request(request, mobile, method, jwt_client_key)

            """ Handle SO and CO """
            if method in ('SO', 'CO'):
                if not req_data.get('otp'):
                    return get_error_response(400, 4001)

                OTP = req_data['otp']
                tsRange = get_ts() - OTP_TIME_LIMIT * 60
                otpQuery = {
                    "query": {
                        "bool": {
                            "must": [
                                {"match": {"mobile": str(mobile)}},
                                {"range": {"creation_time": {"gte": tsRange}}}
                            ]
                        }
                    },
                }
                otp_exists = es_count(OTP_INDEX, otpQuery)
                if not otp_exists:
                    return get_error_response(400, 4001, 'Please Register before Login!')
                else:
                    return self.validate_otp(request, jwt_client_key, mobile, method, OTP)
        except Exception as e:
            return handle_exception(forward_exception(e, 'Login[view]'), request)

