import math, smtplib, re, string, random
import requests, json, jwt
from urllib import parse
from bson import json_util
import random
import environ
from time import time
from operator import itemgetter

from email.message import EmailMessage
from datetime import datetime as dt, timedelta
from base64 import b64encode, b64decode
from django.http import HttpResponse
from django.conf import settings

# AES
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from app.helper.logger import logger
from app.model.elasticModel import es_search
import sys
import traceback

# Import json configs
successMessage = json.load(open('app/config/success_message.json'))
errorMessage = json.load(open('app/config/error_message.json'))
config = json.load(open('app/config/config.json'))
err_codes = json.load(open('app/config/custom_err_codes.json'))

# Email Credentials
EMAIL_FROM       = config['services']['email']['fromEmail']
EMAIL_USER       = config['services']['email']['user']
EMAIL_PASS       = config['services']['email']['pass']
EMAIL_URL        = config['services']['email']['url']
EMAIL_PORT       = config['services']['email']['port']
# SMS Credentials
SMS_URL          = config['services']['sms']['otp_url']
# Flash Call Credentials
FC_URL           = config['services']['flash_call']['url']
FC_AUTH_TOKEN    = config['services']['flash_call']['Authorization']
FC_CALLER_PREFIX = config['services']['flash_call']['callerPrefix']
# OTP SMS Template
OTP_MSG          = config['templates']['sms']['OTP']['msg']
OTP_MSG_TID      = config['templates']['sms']['OTP']['template_id']
# call OTP Credentials
CO_URL           = config['services']['call_otp']['url']
CO_USER          = config['services']['call_otp']['cUser']
CO_TOKEN         = config['services']['call_otp']['cToken']
CO_PLANID        = config['services']['call_otp']['cPlanId']
CO_IVRID         = config['services']['call_otp']['cIvrId']
# SMPP Credentials
SMPP_NAME        = config['services']['smpp']['smpp_name']
SMPP_SYSTEM_ID   = config['services']['smpp']['system_id']
SMPP_PASSWORD    = config['services']['smpp']['password']
SMPP_ROUTE       = config['services']['smpp']['route']
SMPP_LANG        = config['services']['smpp']['lang']
SMPP_TX_PORT     = config['services']['smpp']['port']
SMPP_IP          = config['services']['smpp']['IP']
SMPP_SENDER_ID   = config['services']['smpp']['user_id']

ALLOWED_IMG_EXT  = config['settings']['allowedImgExt']

# GET ENV variables
env = environ.Env()

JWT_SECRET_KEY = env('JWT_SECRET_KEY')
DEFAULT_AES_KEY = env('AES_DAK')
SERVER_PRIVATE_KEY = env('AES_SPK')
TEST_KEY = env('AES_TEST_KEY')

#field indices for lang
FIELD_TYPES  = config['data']['field_types']

""" 
    Common Functions 
    @author: Govind Saini
    @updatedAt: 8th Dec'22
    @desc: commonly used functions in project
    @update: added forwardResponse and exceptionHandler
"""

''' Commonly Used Functions '''
#on correct number
def validate_mob(m):
    m = str(m).strip()
    Pattern = re.compile("(0|91)?[6-9][0-9]{9}")
   
    if(len(m) == 10):
        if(Pattern.match(m) == None): return False
        return True
    elif(len(m) > 10 and len(m) <= 14):
        mob = m[-10:]
        if(Pattern.match(mob)):
            prefix = m[:-10]
            MOBPREFIXES = ["0", "+91", "+91 ", "+91-", "+91-", "91"]
            if prefix in MOBPREFIXES: return True
            else: return False
        else: return False
    else: return False

def translated_data(data, lang = "en"):
    if (lang != "en"):
        for tag in data['tag_list']:
            tag["name"] = tag["lang"].get(lang, tag["name"])

    for tag in data['tag_list']:
        del tag["lang"]
    return data

def translation(field_value ,field, lang = 'en'):
    try:
        word_list = field_value.lower().split(" ")
        translation_query = {
         "query": {
            "terms": {
                 "n.keyword": word_list
                }
            },"_source": ["n", "lang"]
        }
        index = FIELD_TYPES.get(field)

        if field == "company":
            translation_data = (es_search(index, translation_query, exclude_id=True, cluster="c"))
        else:
            translation_data = (es_search(index, translation_query, exclude_id=True))
        translation_dict = {entry["n"]: entry["lang"] for entry in translation_data}
        if not translation_dict:
            return field_value
        translated_word = ""
        for word in word_list:
            if word in translation_dict:
                translated_word += translation_dict[word].get(lang, word) + " "
            else:
                translated_word += word + " "

        translated_word = translated_word.rstrip()
        return translated_word
    except:
        return field_value


def validate_otp(o):
     o = str(o)
     Pattern = re.compile("^[0-9]{6}$")
     if(len(o) == 6):
        return Pattern.match(o)
     else: return False


def send_mail(subject, email, content):
    try:
        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = EMAIL_FROM
        msg['To'] = email

        msg.set_content(content, subtype='html')

        with smtplib.SMTP(EMAIL_URL, EMAIL_PORT) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.ehlo()
            smtp.login(EMAIL_USER, EMAIL_PASS) 
            smtp.send_message(msg)
            smtp.quit()
            return True
    except Exception as e:
        raise Exception('UNKNOWN_ERR', { 'msg': f"send_mail: {e}" })


def send_sms(mobile, otp):
    otp_msg = OTP_MSG.replace('{{otp}}', str(otp)).replace('{{other_msg}}', "Kc7yL4%2B17G%2B")
    sms_url = SMS_URL.replace('{{mobiles}}', str(mobile)).replace('{{template_id}}', str(OTP_MSG_TID)).replace('{{template}}', str(otp_msg))
    headers = { 'cache-control': "no-cache" }
    
    try:
        resp = requests.request("GET", sms_url, headers = headers)
    except Exception as e:
        raise Exception('Error While sending the SMS', { 'msg': f"sendSMS: {e}" })


def otpgen():
    try:
        otp = ""
        otp = random.randint(100000, 999999)
        return int(otp)
    except Exception as e:
        raise Exception('UNKNOWN_ERR', { 'msg': f"otpgen: {e}" })


def originate_call(mobile):
    mobile = str(mobile)
    FC_CALLER_POSTFIX = str(math.floor(random.randint(0,19998)) + 18701)
    caller_id = FC_CALLER_PREFIX + FC_CALLER_POSTFIX

    URL = FC_URL.replace("{{callerId}}", caller_id).replace("{{mobile}}", mobile)
    try:
        response = requests.request("POST", URL, headers = { 'Authorization': FC_AUTH_TOKEN })
        return response.text
    except Exception as e:
        raise Exception('UNKNOWN_ERR', { 'msg': f"originateCall: {e}" })


def otp_call(mobile, otp):
        mobile = str(mobile)
        otp = ",".join(list(str(otp)))

        url = CO_URL.replace("{{mobile}}", mobile).replace("{{cUser}}", CO_USER).replace("{{cToken}}", CO_TOKEN)\
                .replace("{{cPlanId}}", CO_PLANID).replace("{{cIvrId}}", CO_IVRID).replace("{{otp}}", otp)
        try:
            response = requests.request("GET", url)
            return response.text
        except Exception as e:
            raise Exception('UNKNOWN_ERR', { 'msg': f"otp_call: {e}" })


def get_time_stamp():
    return int(time()) * 1000

def is_empty_str(val):
    return True if val == '' else False

def get_iso_date():
    return dt.now() - timedelta(hours = 5, minutes=30)

def gen_user_id():
    return (gen_rand_str(4) + hex(int(time()))[3:]).upper()

def generate_token(payload):
    try:
        encoded = jwt.encode(payload, JWT_SECRET_KEY, algorithm = "HS256")
        decoded = str(encoded)

        return json.loads(json_util.dumps({'data': { 'token': decoded }}))
    except Exception as e:
        raise Exception('TOKEN_ERR', { 'msg': f"generate_token: {e}", 'code': 500, 'subcode': 5001 })


def decode_token(token):
    try:
        decode_token = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
        return decode_token 
    except Exception as e:
        raise Exception('TOKEN_ERR', { 'msg': f"decode_token: {e}" })


def validate_email(email):
    try:
        regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        if(re.fullmatch(regex, email)): return True
        return False
    except Exception as e:
        raise Exception('UNKNOWN_ERR', { 'msg': f"validate_email: {e}" })
  

def is_valid_image(ext):
    try: 
       if ext in ALLOWED_IMG_EXT: return True
       return False 
    except Exception as e:
        raise Exception('UNKNOWN_ERR', { 'msg': f"is_valid_image: {e}" })
    

def validate_name(name):
    try: 
      regex_name = re.compile(r'([a-z]+)( [a-z]+)*( [a-z]+)*$', re.IGNORECASE)
      if(regex_name.search(name)): return True
      return False     
    except Exception as e:
        raise Exception('UNKNOWN_ERR', { 'msg': f"validate_name: {e}" })


def validate_dob(date):
    try:
        day, month, year = date.split('/')
        dt(int(year), int(month), int(day))
        if(dt.now().year < int(year) + 14):
            raise Exception('INVALID_REQUEST', { 'subcode': 40014, 'msg': 'Age is too short!' })
        return True
    except ValueError:
        return False
    except Exception as e:
        raise forward_exception(e, 'validate_dob')


def validate_cc(o):
    o = str(o)
    o = re.sub('\+', '', o)

    pat = re.compile('[0-9]+')
    if len(o) < 4: return pat.match(o)
    else: return False


def get_success_response(status, sub_status, data=None, msg=None):
    status = str(status)
    sub_status = str(sub_status)
    result = {
        'success': True,
        'code': sub_status,
        'msg': successMessage[status][sub_status] if not msg else msg,
        'data': data
    }
    response = HttpResponse(json.dumps(result), content_type='application/json')
    response.status_code = int(status)
    return response



def get_error_response(status, sub_status, msg=None):
    status = str(status)
    sub_status = str(sub_status)
    result = {
        'success': False,
        'code': sub_status,
        'data': None,
        'msg': errorMessage[status][sub_status] if not msg else msg
    }
    response = HttpResponse(json.dumps(result), content_type='application/json')
    response.status_code = int(status)
    return response

def forward_response(status, data):
    response = HttpResponse(json.dumps(data), content_type='application/json')
    response.status_code = int(status)
    return response


## @author:: Govind Saini - 21st Nov'22
## @info:: AES Encrption/Decryption Utils

def select_aes_key(key):
    if key == 'SPK':
        return SERVER_PRIVATE_KEY
    elif key == 'DAK':
        return DEFAULT_AES_KEY
    else: return key


def decrypt_data(enc_data, key):
    try:
        key = select_aes_key(key)
        key = bytes(key, 'utf-8')

        data_bytes = b64decode(enc_data.encode('utf-8'))
        aes = AES.new(key, AES.MODE_ECB)    
        data = unpad(aes.decrypt(data_bytes), AES.block_size)
        return data.decode()
    except Exception as e:
        raise Exception('INVALID_ENC', { 'msg': str(e) })


def encrypt_data(data, key):
    try:
        key = select_aes_key(key)
        key = bytes(key, 'utf-8')

        data_bytes = bytes(data, 'utf-8')
        padded_bytes = pad(data_bytes, AES.block_size)

        cipher = AES.new(key, AES.MODE_ECB)
        enc_data = cipher.encrypt(padded_bytes)
        b64_data = b64encode(enc_data).decode('utf-8')
        return b64_data
    except Exception as e:
        raise Exception('INVALID_ENC', { 'msg': str(e), 'code': 500, 'subcode': 5001 })


def gen_rand_str(n):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k = n))


def gen_hash_mob_code(mobile):
    mobile = hex(int(mobile))
    
    ts_str, ms_str = str(time())[5:].split('.')
    ts_str, ms_str = oct(int(ts_str)), int(ms_str, 32)
    hash = f"{ms_str}.{ts_str}.{mobile}.{gen_rand_str(16)}"
    return "Naam-RG-" + b64encode(hash.encode("ascii")).decode("ascii")


def forward_exception(e, msg=None, code=None, subcode=None):
    if len(e.args) > 1 and type(e.args[1]) is dict:
        if msg:
            if e.args[1].get('msg'):
                e.args[1]['msg'] += ' > ' + msg
            else: e.args[1]['msg'] = msg
            
        if code: e.args[1]['code'] = code
        if subcode: e.args[1]['subcode'] = subcode
    return e


def handle_exception(e, request):
    try:
        def get_val(dict, key, default):
            return dict[key] if dict.get(key) else default
        def get_error_data(errDesc, code=None, subcode=None):
            code, subcode = str(code), str(subcode)
            errData = e.args[1] if len(e.args) > 1 and type(e.args[1]) is dict else None
            if not errData:
                logger.error(errDesc + errorMessage[code][subcode])
                return get_error_response(code, subcode)
            code = str(get_val(errData, 'code', code))
            subcode = str(get_val(errData, 'subcode', subcode))
            msg = get_val(errData, 'msg', errorMessage[code][subcode])
            # logger.info(f'---hi--{code} {subcode} {msg}')
            logger.error(errDesc + msg)
            return get_error_response(code, subcode)
        
        errName = e.args[0]
        if(errName in err_codes):
            code, subcode, errDesc = itemgetter('code', 'subcode', 'msg')(err_codes[errName])
            if code is 500:
                recipient_list = [admin[1] for admin in settings.ADMINS]
                name = request._userInfo['record'].get('first_name', None)
                if name is None:
                    subject = 'Server Exception Occurred in Naam Production by {}'.format(request._userInfo['mobile'])
                else:
                    subject = 'Server Exception Occurred in Naam Production by {} and name is {}'.format(
                        request._userInfo['mobile'], name)
                send_mail(subject, recipient_list, get_error_data(errDesc, code, subcode))
            return get_error_data(errDesc, code, subcode)
        else:
            logger.error(err_codes['UNKNOWN_ERR']['msg'] + str(e))
            if str(e).startswith('JSON parse error'):
                return get_error_response(400, 4001, 'Invalid JSON string!')   
            elif str(e).startswith('Expecting value'):
                return get_error_response(400, 4001, 'Invalid request format!')
            else:
                exc_type, exc_value, tb = sys.exc_info()
                message = f'<div style="background:#e2e8f0;padding:10px;border-left:0.4em solid red"><b>Error::</b> {exc_value}<br/><b>Stack::</b> {traceback.format_tb(tb)}<br/></div>'
                recipient_list = [admin[1] for admin in settings.ADMINS]
                name = request._userInfo['record'].get('first_name', None)
                if name is None:
                    subject = 'Server Exception Occurred in Naam Production by {}'.format(request._userInfo['mobile'])
                else:
                    subject = 'Server Exception Occurred in Naam Production by {} and name is {}'.format(
                        request._userInfo['mobile'], name)
                send_mail(subject, recipient_list, message)
            return get_error_response(500, 5001)
    except Exception as e:
        logger.error(f"handle_exception[C.F.]: {e}")
        return get_error_response(500, 5001)