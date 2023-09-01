import json
import math
import re
from datetime import datetime
import traceback
from app.helper.log_methods import Info, Error, Critical, Warn, SysLog
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
            Info('LOG', "Create Token Hit")
            if "ck" not in request.headers or "mobile" not in request.headers:
                Error('INVALID_HEADERS', 'ck or mobile is not in headers')
                raise Exception("INVALID_HEADERS")

            ck = request.headers["ck"]
            mobile = request.headers["mobile"]
            payload = {}

            if Pattern.match(mobile):
                Info('LOG', 'Testing account number', extra_data = {'result': mobile} )
                payload["testingAccount"] = "testingAccount"
            else:
                mobRes = validate_mob(mobile)
                if not mobRes:
                    Error('INVALID_REQUEST', 'Invalid mobile!', extra_data = {'result': mobile})
                    raise Exception("INVALID_REQUEST", {"subcode": 4003})
                mobile = mobile[-10:]

            if len(ck) == 0:
                Error('INVALID_HEADERS','Invalid/missing ck!')
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

            Info('LOG', 'Payload while creating token', extra_data = payload)

            data = generate_token(payload)["data"]
            return get_success_response(200, 2001, data)

        except Exception as e:
            stack_trace = traceback.format_exc()
            Error('TOKEN_ERR', e.args[0], traceback=stack_trace)
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
        Info('LOG', 'find_signup_log: Result of signup log find from USER_LOGS_INDEX', extra_data = {'result':search_result})
        return search_result
    except Exception as e:
        stack_trace = traceback.format_exc()
        Error('UNKNOWN_ERR',f"While finding signup log: {e.args[0]}", traceback=stack_trace)
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
            Info('LOG', 'find_otp_log: Result from OTP_INDEX', extra_data = {'result': result})
            return result[0] if len(result) > 0 else None
        except Exception as e:
            stack_trace = traceback.format_exc()
            Error('UNKNOWN_ERR',f"While finding otp log for mobile {mobile}: {e.args[0]}", traceback=stack_trace)
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

            Info('LOG', 'insert_otp_log: inserting payload of otp in OTP_INDEX', extra_data = insert_obj)
            es_insert(OTP_INDEX, insert_obj)
            return otp
        except Exception as e:
            stack_trace = traceback.format_exc()
            Error('UNKNOWN_ERR',f"While insert otp log for mobile {mobile}: {e.args[0]}", traceback=stack_trace)
            raise forward_exception(e, 'insert_otp_log')

    def create_signup_request(self, request, mobile, method,otp, enc_key=None, set_obj=None):
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

                Info('LOG', 'create_signup_request:  Insert fresh log for signup request in USER_LOGS_INDEX', extra_data = insert_obj)
                insert_res = es_insert(USER_LOGS_INDEX, insert_obj)
                if insert_res == "created":
                    update_res = True

            # Send response to user.
            if update_res:
                whatsapp = {'otp': otp}
                encrypted_data = encrypt_data(json.dumps(whatsapp), enc_key)
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
                Error('UNKNOWN_ERR','Unable to update signup log!')
                raise Exception('Unable to update signup log!')
        except Exception as e:
            stack_trace = traceback.format_exc()
            Error('UNKNOWN_ERR',f"While creating signup req: {e.args[0]}", traceback=stack_trace)
            return handle_exception(forward_exception(e, 'SignUp-CSR[view]'), request)



    def send_otp(self, request, mobile, method, otp, CGK):
        if method == "SO":
            Info('LOG', 'Sending sms otp', extra_data = {'mobile':mobile, 'otp': otp})
            send_sms(mobile, otp)
            # send_sms_SMPP(mobile, otp)
        elif method == "CO":
            Info('LOG', 'Sending call otp', extra_data = {'mobile':mobile, 'otp': otp})
            otp_call(mobile, otp)

        return self.create_signup_request(request, mobile, method, otp, enc_key=CGK)



    def post(self, request):
        try:
            mobile = request._userInfo['mobile']
            CGK = request._userInfo['CGK']
            
            # if 'testingAccount' in request._userInfo:
            #     testingAccount = request._userInfo['testingAccount']



            # req validations
            if 'data' not in request.data or not isinstance(request.data['data'], str):
                Error('INVALID_REQUEST', "Encrypted data not found" )
                return get_error_response(400, 4002)

            req_data = json.loads(decrypt_data(request.data['data'], CGK))
            if('method' not in req_data): 
                Error('INVALID_HEADERS', 'method not found in req_data')
                return get_error_response(400, 4002)
            
            

            method = req_data['method']
            if method not in methodList:
                Error('INVALID_HEADERS',"Invalid Method!", extra_data = {'method': method})
                return get_error_response(400, 4005)

            if 'testingAccount' in request._userInfo and method != "SO":
                Error('INVALID_HEADERS','Invalid headers while req testing account!')
                return get_error_response(400, 4005)
                # testingAccount = request._userInfo['testingAccount']
        

            # handle signup methods
            if(method == "FC"):
                raise Exception('code fat go!')
                """ Handle Signup via FC """
                call_resp = originate_call(mobile)

                if(not call_resp):
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

            elif(method == "CO" or method == "SO" or method == "WA"):
                """ Handle Signup via SO/CO """
                otp_log = self.find_otp_log(mobile)

                if not otp_log:
                    Info('LOG', 'No log found for the user so inserting new otp log', extra_data = {'mobile':mobile})
                    otp = self.insert_otp_log(mobile)
                    return self.send_otp(request, mobile, method, otp, CGK)
                else:
                    if(otp_log.get("block_time") is None):
                        otp = otp_log['OTP']
                        retry_count = otp_log['retry_count']
                        last_req_ts = otp_log['updation_time'] if otp_log.get("updation_time") is not None else otp_log['creation_time']
                        time_diff = math.ceil((get_ts() - last_req_ts)/60000) # time diff in mins

                        if(time_diff >= SIGNUP_TTL or retry_count >= RESEND_OTP_LIMIT):
                            # re-generate otp
                            Info('LOG', 'Regenerating new OTP because of RESEND_OTP_LIMIT or SIGNUP_TTL is reached')
                            otp = otpgen()
                            set_obj = { "OTP": otp, "updation_time": get_ts(), "retry_count": 0 }
                            es_update_by_id(OTP_INDEX, otp_log['_id'], set_obj)
                        else:
                            Info('LOG', 'retry count incremented by 1')
                            inc_script = { "source": "ctx._source.retry_count++;" }
                            es_update_by_id(OTP_INDEX, otp_log['_id'], script = inc_script)

                        # Resend OTP
                        Info('LOG', 'Resending OTP!', extra_data = {'mobile':mobile, 'otp':otp, 'method':method })
                        return self.send_otp(request, mobile, method, otp, CGK)
                    else:
                        # send error msg with how much time left in re-req
                        time_diff = USER_BLOCK_TIME - (get_ts() - otp_log['block_time']) # in mins
                        time_diff = math.ceil(time_diff/60000)

                        # if block time is finish
                        if time_diff <= 0:
                            otp = otpgen()
                            update_script = {
                                "source": "ctx._source.OTP = params.otp;ctx._source.updation_time = params.updation_time;ctx._source.retry_count = params.retry_count;ctx._source.wrong_count=0;ctx._source.remove('block_time')",
                                "lang": "painless",
                                "params": { "otp": otp, "updation_time": get_ts(), "retry_count":0  }
                            }
                            
                            es_update_by_id(OTP_INDEX, otp_log['_id'], script = update_script)
                            return self.send_otp(request, mobile, method, otp, CGK)
                        else:
                            Error('TEMPORARY_BLOCKED', f'User is blocked and time left to unblock is: {time_diff}', extra_data = {'mobile':mobile})
                            return get_error_response(403, 4031, f"The OTP limit has been exceeded. Please try again after {time_diff} minutes.")
                        
        except Exception as e:
            stack_trace = traceback.format_exc()
            Error('UNKNOWN_ERR', e.args[0], traceback=stack_trace)
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
            Info('LOG', 'update_user_as_verified: Getting Login user from m_index to append verified', extra_data = {'result':search_result})
            caller_info = search_result[0]
            user_id = caller_info['_id']
            user_status = caller_info['user_type'] if caller_info.get('user_type') else []

            if 'verified' not in user_status:
                user_status.append('verified')
                es_update_by_id(m_index, user_id, {'user_type': user_status})

    def create_login_request(self, request, mobile, method, jwt_client_key, caller_id=None, otp_id=None, device_info=None):
        try:
            vrf_status = 1 if method == 'SS' else 0
            log_info = find_signup_log(mobile, method, vrf_status)

            if len(log_info):
                log_id = log_info[0]['_id']

                # check if same caller_id for FC
                if method == 'FC' and log_info[0]['caller_id'][-10:] != str(caller_id):
                    Error('UNKNOWN_ERR',"Invalid caller_id!")
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

                        if device_info:
                            device_info['created_dt'] = get_ts()
                            if user_res[0].get('device_info'):
                                source = "ctx._source.login_type = params.login_type;ctx._source.last_login = params.last_login;ctx._source.device_info.add(params.device_info)"
                            else:
                                source = "ctx._source.login_type = params.login_type;ctx._source.last_login = params.last_login;ctx._source.device_info = [params.device_info]"

                            update_script = {
                                    "source": source,
                                    "lang": "painless",
                                    "params": { "login_type": method, "last_login": get_ts(), 'device_info': device_info }
                                }

                            es_update_by_id(USER_INDEX, user_res[0]['_id'], script=update_script)
                        else:
                            es_update_by_id(USER_INDEX, user_res[0]['_id'], user_info)
                    else:
                        user_id = gen_user_id()
                        if device_info:
                            device_info['created_dt'] = get_ts()
                            user_info.update({'user_id': user_id, 'mobile': mobile, 'created_dt': get_ts(), 'device_info': [device_info]})
                        else:
                            user_info.update({'user_id': user_id, 'mobile': mobile, 'created_dt': get_ts()})
                        es_insert(USER_INDEX, user_info)

                    # if SO/CO delete otp record before serving response
                    if method == 'SO' or method == 'CO' or method == "WA":
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
                    Info('LOG', 'create_login_request: user succesfully updated verified and token created', extra_data = {'result': payload})
                    return get_success_response(200, 2002, data)
                else:
                    Error('UNKNOWN_ERR',"Unable to update user log!", extra_data = {'mobile':mobile})
                    return get_error_response(500, 5002)
            else:
                if method == 'SS':
                    Error('UNKNOWN_ERR',"Unable to validate message in SS!", extra_data = {'mobile':mobile})
                    return get_error_response(404, 4041, "Unable to validate message!")
                else:
                    Error('UNKNOWN_ERR',"No Logs Found for the User", extra_data = {'mobile':mobile})
                    return get_error_response(404, 4041)
        except Exception as e:
            stack_trace = traceback.format_exc()
            Error('UNKNOWN_ERR',f"While creating login request: {e.args[0]}", traceback=stack_trace)
            return handle_exception(forward_exception(e, 'Login-CSR[view]'), request)

    def validate_otp(self, request, jwt_client_key, mobile, method, otp, device_info):
        try:
            Info('LOG', 'Validating otp', extra_data = {'mobile':mobile, 'otp':otp, 'method':method})
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
                    time_diff = USER_BLOCK_TIME - (get_ts() - otp_details[0]['block_time'])   # in mins
                    time_diff = math.ceil(time_diff/60000)

                    # if block time is finish
                    if time_diff <= 0:
                        Error('LOG',"User was blocked but block time is over now, Register before Login!", extra_data = {'mobile':mobile})
                        return get_error_response(400, 4001, 'Please Register before Login!')
                    else:
                        Error('TEMPORARY_BLOCKED', f'User is blocked and time left to unblock is: {time_diff}', extra_data = {'mobile':mobile})
                        return get_error_response(403, 4031, f"The OTP limit has been exceeded. Please try again after {time_diff} minutes.")


                # check if user OTP is equal to DB(Stored) OTP
                if str(otp) == str(actual_otp):
                    return self.create_login_request(request, mobile, method, jwt_client_key, otp_id=otp_id, device_info=device_info)
                else:
                    update_script = {
                        "source": "ctx._source.wrong_count++;",
                        "lang": "painless",
                        "params": {
                            "block_time": get_ts()
                        }
                    }
                    
                    if (wrong_count + 1 == WRONG_OTP_LIMIT) and not Pattern.match(mobile):
                        update_script['source'] += "ctx._source.block_time = params.block_time"

                    es_update_by_id(OTP_INDEX, otp_id, script=update_script)

                    Error('WRONG_OTP', 'otp does not match with DB otp', extra_data = {'mobile':mobile})
                    return get_error_response(400, 4004)
            else:
                Error('LOG',"OTP Not Exists/requested!", extra_data = {'mobile':mobile})
                return get_error_response(500, 5001)

        except Exception as e:
            stack_trace = traceback.format_exc()
            Error('UNKNOWN_ERR',f"While validate otp: {e.args[0]}", traceback=stack_trace)
            raise forward_exception(e, 'validate_otp')

    def post(self, request):
        try:
            mobile = request._userInfo['mobile']
            jwt_client_key = request._userInfo['ck']
            CGK = request._userInfo['CGK']

            # Request validations
            if 'data' not in request.data or not isinstance(request.data['data'], str):
                Error('INVALID_REQUEST',"Encrypted data not found!")
                return get_error_response(400, 4002)

            req_data = json.loads(decrypt_data(request.data['data'], CGK))
            Info("LOG", "Login: request data", extra_data = {'result':req_data})

            if 'method' not in req_data:
                Error('INVALID_HEADERS',"Method not found!")
                return get_error_response(400, 4002)

            method = req_data['method']
            if method not in methodList:
                Error('INVALID_HEADERS',"Invalid method!",extra_data={'method':method})
                return get_error_response(400, 4005)
            
            
            device_info = req_data['device_info'] if 'device_info' in req_data else None

            # Handle signup verification
            """ Handle SS and FC """
            if method == 'FC':
                if 'caller_id' not in req_data:
                    Error('LOG',"caller_id not found!")
                    return get_error_response(400, 4002, 'caller_id not found!')
                return self.create_login_request(request, mobile, method, jwt_client_key, req_data['caller_id'])

            if method == 'SS':
                return self.create_login_request(request, mobile, method, jwt_client_key)

            """ Handle SO and CO """
            if method in ('SO', 'CO','WA'):
                if not req_data.get('otp'):
                    Error('LOG',"OTP not found")
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
                    Error('LOG',"otp not exists, Register before Login!")
                    return get_error_response(400, 4001, 'Please Register before Login!')
                else:
                    return self.validate_otp(request, jwt_client_key, mobile, method, OTP, device_info=device_info)
        except Exception as e:
            stack_trace = traceback.format_exc()
            Error('UNKNOWN_ERR', e.args[0], traceback=stack_trace)
            return handle_exception(forward_exception(e, 'Login[view]'), request)

