import json, requests, time, environ
import threading, os
import traceback
from rest_framework.views import APIView
from operator import itemgetter
from django.conf import settings
from app.model.minioModel import minio_client
from app.model.elasticModel import es_search, es_insert, es_update_by_id

from app.helper.commonFunction import get_time_stamp as get_ts, gen_rand_str, validate_mob, get_error_response, get_success_response, validate_name, send_mail, is_valid_image, validate_email, validate_otp, validate_dob, handle_exception, forward_exception, is_empty_str, translated_data, translation	
from ..apps import get_tag_cache	
from copy import deepcopy
from app.helper.log_methods import Info, Error, Critical, Warn

# Env Variables	
API_BASE_URL = os.environ.get('API_BASE_URL')
MINIO_BUCKET_URL = os.environ.get('MINIO_BUCKET_URL')


config = json.load(open('app/config/config.json'))

# Indexes/Collections
ES_INDICES       = config['data']['elastic']['indices']
PIN_INDEX        = ES_INDICES['pincodes']
FEEDBACK_INDEX   = ES_INDICES['feedback']
USER_PERMISSION_INDEX = ES_INDICES["user_permission"]
EMAIL_VERIFY_INDEX = ES_INDICES["email_verification"]
TAGS_INDEX       = ES_INDICES['tags']
USER_INDEX       = ES_INDICES['users']
IMAGE_INDEX      = ES_INDICES['image']
DETAILS_INDEX    = ES_INDICES['details']
BLOCK_INDEX      = ES_INDICES['blocker']
SPAM_INDEX       = ES_INDICES['spam_check']

# Default Confs.
UPDATE_KEYS      = set(config['settings']['updateProfileKeys'])
RAND_CHAR_IMG    = config['settings']['RandomCharInUserImg']
EMAIL_TOKEN_SIZE = config['settings']['emailTokenSize']
GENDER_LIST      = config['settings']['genderList']
NAME_LIMIT       = config['settings']['nameLimit']

EMAIL_LIMIT      = config['settings']['emailLimit']
EMAIL_SUBJECT    = config['templates']['email']['verification']['subject']
EMAIL_MESSAGE    = config['templates']['email']['verification']['message']
EMAIL_VERIFICATION_TTL      = config['settings']['emailVerificationTTL']
# Bucket Confs.
APP_BUCKET         = config['data']['minio']['buckets']['app']
APP_BUCKET_URL     = MINIO_BUCKET_URL + APP_BUCKET 
TAG_URL_PREFIX     = APP_BUCKET_URL + '/assets/tags/'
PROFILE_URL_PREFIX = APP_BUCKET_URL + '/users/'
FIELD_LIST = ["first_name", "last_name","city", "company"]	

TAG_CACHE_LOCK = threading.Lock()

TYPES = config['data']['type']
""" 
    User Views 
    @author: Govind Saini
    @updatedAt: 4th Dec'22
    @desc: related to user settings and personal information
    @update: updated myProfile, setPincode, userFeedback and tags view, and commented email APIs
    @added: added timestamp in feedback
    @removed: improper validate_name on feedback string
"""

def send_verification_email(email: str, mobile: str) -> bool:
    try:
        # Check if recent un-verified mail request exists; if so, send the same mailURL again until TTL
        range_time = get_ts() - EMAIL_VERIFICATION_TTL * 60  # 30 mins before (30*60)
        query = {
            "query": {
                "bool": {
                    "filter": [
                        {"match": {"email": email}},
                        {"match": {"status": 0}},
                        {"match": {"mobile": mobile}},
                        {"range": {"creation_time": {"gte": range_time}}}
                    ]
                }
            },
            # "sort": [{"creation_time": "desc"}]
        }

        search_result = es_search(EMAIL_VERIFY_INDEX, query)

        ## if len(search_result) == 0 or (search_result[0]['email'] == email and search_result[0]['status'] == 0): // cross-case
        if len(search_result) == 0:
            # Insert new log
            salt = gen_rand_str(EMAIL_TOKEN_SIZE)
            insert_obj = {
                "creation_time": get_ts(),
                "mobile": mobile,
                "salt": salt,
                "status": 0,
                "email": email
            }

            es_insert(EMAIL_VERIFY_INDEX, insert_obj)
        else:
            # Use same salt
            salt = search_result[0]['salt']

        v_link = f'{API_BASE_URL}api/v1/user/verify_email/{salt}'
        content = EMAIL_MESSAGE.replace('{{vLink}}', v_link)

        send_mail(EMAIL_SUBJECT, email, content)
        return True
    except Exception as e:
        stack_trace = traceback.format_exc()
        Error('MAIL_ERR',f"While processing mail: {e.args[0]}", traceback=stack_trace)
        return False


def translatefields(user_info, lang):	
    for field in FIELD_LIST:	
        if user_info.get(field) and lang != "en":	
            user_info[field] = translation(user_info[field], field, lang)	
    Info('LOG', f'translatefields: {user_info}', extra_data = {'lang':lang})
    return user_info	

def get_valid_cache():	
    try:	
        # acquire the lock before accessing/modifying the cache	
        TAG_CACHE_LOCK.acquire()	
        TAG_CACHE = settings.TAGS_CACHE	
        # check if cached data is valid	
        if (time.time() > TAG_CACHE.get('exp', 0)):	
            TAG_CACHE = get_tag_cache()	
            data = TAG_CACHE.get('data')	
        else:	
            data = TAG_CACHE.get('data')	
        	
        return data	
    except Exception as e:	
        stack_trace = traceback.format_exc()
        Error('UNKNOWN_ERR', f'unable to load the tag cache data: {e.args[0]}', traceback=stack_trace)
    finally:	
        # release the lock after accessing/modifying the cache	
        TAG_CACHE_LOCK.release() 	



# for get user self profile
class MyProfile(APIView):
    def file_upload(self, mobile, img):
        try:
            image_query = {"query": {"match": {"mobile": mobile}}, "size": 1}
            image_info = es_search(IMAGE_INDEX, image_query)

            mob_leading_chars = mobile[:6]
            file_name, file_size, user_file = img.name, img.size, img.file
            ext = file_name[file_name.rfind('.'):]

            rand_str = gen_rand_str(RAND_CHAR_IMG)
            save_file_name = mobile + "-" + rand_str + ext
            save_file_path = f"users/{mob_leading_chars}/{save_file_name}"

            if not is_valid_image(ext):
                Error('INVALID_REQUEST','Unsupported media format!', extra_data = {'ext': ext})
                raise Exception('UNSUPPORTED_MEDIA', {'subcode': 4152})

            minio_client.put_object(APP_BUCKET, save_file_path, user_file, file_size)
            updated_info = {}
            if image_info:
                Info('LOG', f'Image info found in {IMAGE_INDEX} for user {mobile}', extra_data = {'result':image_info})
                image_info = image_info[0]

                list_images_user = image_info['u_img']
                if not list_images_user:
                    list_images_user = []
                list_images_user.append(rand_str + ext)

                image_info['u_img'], image_info['updated_dt'] = list_images_user, get_ts()
                # ?? use update_by_id here
                updated_res = es_insert(index=IMAGE_INDEX, doc=image_info, id=image_info.pop('_id'))
            else:
                Info('LOG', f'Image info NOT found in {IMAGE_INDEX} for user {mobile}')
                updated_info['u_img'], updated_info['updated_dt'], updated_info['mobile'] = [rand_str], get_ts(), mobile
                updated_res = es_insert(index=IMAGE_INDEX, doc=updated_info)

            if not updated_res:
                Error('UNKNOWN_ERR',"Failed to update user-profile picture in elastic",extra_data = {'mobile':mobile})
                return get_error_response(500, 5002)

            return {'profile_pic': save_file_name}
        except Exception as e:
            stack_trace = traceback.format_exc()
            Error('MINIO_ERR', e.args[0], traceback=stack_trace)
            raise forward_exception(e, 'file_upload')

    def scan_data(self, data):
        update_obj = {}
        resp_obj = {}
        reset_obj = []

        if 'profile_pic' in data:
            profile_pic = data['profile_pic'].strip()
            reset = is_empty_str(profile_pic)

            if (reset):
                reset_obj.append('profile_pic')
            else:
                update_obj['profile_pic'] = profile_pic

        if 'first_name' in data:
            first_name = data['first_name'].strip()
            reset = is_empty_str(first_name)

            if (reset):
                reset_obj.append('first_name')
            else:
                if (not validate_name(first_name) or len(first_name) > NAME_LIMIT):
                    resp_obj['err'] = (400, 40011, "Please enter valid first name!")
                    return resp_obj

                update_obj['first_name'] = first_name

        if 'last_name' in data:
            last_name = data['last_name'].strip()
            reset = is_empty_str(last_name)
            if (reset):
                reset_obj.append('last_name')
            else:
                if (not validate_name(last_name) or len(last_name) > NAME_LIMIT):
                    resp_obj['err'] = (400, 40011, "Please enter valid last name!")
                    return resp_obj

                update_obj['last_name'] = last_name

        if 'sec_mobile' in data:
            sec_mobile = data['sec_mobile'].strip()
            reset = is_empty_str(sec_mobile)

            if (reset):
                reset_obj.append('sec_mobile')
            else:
                if not validate_mob(sec_mobile):
                    resp_obj['err'] = (400, 4003, "Please enter valid mobile!")
                    return resp_obj

                update_obj['sec_mobile'] = sec_mobile

        if 'email' in data:
            email = data['email'].strip()
            reset = is_empty_str(email)

            if (reset):
                reset_obj.append('email')
                reset_obj.append('email_vrf')
            else:
                if (not validate_email(email) or len(email) > EMAIL_LIMIT):
                    resp_obj['err'] = (400, 4008, "Please enter valid email!")
                    return resp_obj

                update_obj['email'] = email

        if 'dob' in data:
            dob = data['dob'].strip()
            reset = is_empty_str(dob)

            if (reset):
                reset_obj.append('dob')
            else:
                if validate_dob(dob):
                    update_obj['dob'] = '/'.join(dob.split('/')[::-1])
                else:
                    resp_obj['err'] = (400, 4009, "Please enter valid/accepted D.O.B. format!")
                    return resp_obj

        if 'gender' in data:
            gender = data['gender'].strip().lower()
            reset = is_empty_str(gender)

            if (reset):
                reset_obj.append('gender')
            else:
                if gender not in GENDER_LIST:
                    resp_obj['err'] = (400, 40012, "Please enter valid gender option!")
                    return resp_obj

                update_obj['gender'] = gender

        if 'country' in data:
            country = data['country'].lower()
            if(country == "india"): update_obj['country'] = "india"
            else:
                resp_obj['err'] = (400, 4001, "Currently india allowed only!")
                return resp_obj

        if 'pincode' in data:
            pincode = str(data['pincode'])
            reset = is_empty_str(pincode.strip())

            if (reset):
                reset_obj.append('pincode')
            else:
                if not validate_otp(pincode):
                    resp_obj['err'] = (400, 40010, "Please enter valid pin!")
                    return resp_obj
                # if we do not allow user to enter city/state manually we may check if pin exists in db
                update_obj['pincode'] = pincode

        if 'city' in data:
            city = data['city'].strip().lower()
            reset = is_empty_str(city)

            if (reset):
                reset_obj.append('city')
            else:
                #?? validate for alphabetic value only
                update_obj['city'] = city

        # if someone enters valid pin, we can get city/state/etc. internally
        if 'street' in data:
            street = data['street'].strip()
            update_obj['street'] = street

        if 'company' in data:
            company = data['company'].strip()
            update_obj['company'] = company

        if 'designation' in data:
            designation = data['designation'].strip()
            update_obj['designation'] = designation

        if 'website' in data:
            website = data['website'].strip()
            update_obj['website'] = website

        if 'about_me' in data:
            about_me = data['about_me'].strip()
            update_obj['about_me'] = about_me

        if 'tag_id' in data:
            # validate tag_id on the basis of existing tags
            tag_id = data['tag_id'].strip()
            reset = is_empty_str(tag_id)


            if (reset):
                reset_obj.append('tag_id')
            else:
                tag_query = { "query": { "match": { "_id" : tag_id }}, "size": 1 }
                tag_info = es_search(TAGS_INDEX, tag_query)

                if not len(tag_info):
                    resp_obj['err'] = (400, 40013, "Invalid tag for update!")
                    return resp_obj
                update_obj['tag_id'] = tag_id

        resp_obj['data'] = update_obj
        resp_obj['reset'] = reset_obj
        return resp_obj

    # def scan_data(self, data):
    #     fields = {
    #         'profile_pic': ('profile_pic',),
    #         'first_name': ('first_name', validate_name, NAME_LIMIT, 40011, 'Please enter valid first name!'),
    #         'last_name': ('last_name', validate_name, NAME_LIMIT, 40011, 'Please enter valid last name!'),
    #         'sec_mobile': ('sec_mobile', validate_mob, None, 4003, 'Please enter valid mobile!'),
    #         'email': ('email', validate_email, EMAIL_LIMIT, 4008, 'Please enter valid email!'),
    #         'dob': ('dob', validate_dob, None, 4009, 'Please enter valid/accepted D.O.B. format!'),
    #         'gender': ('gender', GENDER_LIST, None, 40012, 'Please enter valid gender option!'),
    #         'country': ('country', ('india',), None, 4001, 'Currently india allowed only!'),
    #         'pincode': ('pincode', validate_otp, None, 40010, 'Please enter valid pin!'),
    #         'city': ('city',),
    #         'street': ('street',),
    #         'company': ('company',),
    #         'designation': ('designation',),
    #         'website': ('website',),
    #         'about_me': ('about_me',),
    #         'tag_id': ('tag_id',),
    #     }
    #
    #     update_obj = {}
    #     resp_obj = {}
    #     reset_obj = []
    #
    #     for key, (field, *validators, err_code, err_msg) in fields.items():
    #         if key not in data:
    #             continue
    #
    #         value = data[key].strip()
    #         reset = is_empty_str(value)
    #
    #         if reset:
    #             reset_obj.append(field)
    #         else:
    #             for validator in validators:
    #                 if validator is None:
    #                     continue
    #
    #                 if not validator(value):
    #                     resp_obj['err'] = (400, err_code, err_msg)
    #                     return resp_obj
    #
    #             update_obj[field] = value
    #
    #     if 'tag_id' in update_obj:
    #         tag_query = {"query": {"match": {"_id": update_obj['tag_id']}}, "size": 1}
    #         tag_info = es_search(TAGS_INDEX, tag_query)
    #
    #         if not len(tag_info):
    #             resp_obj['err'] = (400, 40013, "Invalid tag for update!")
    #             return resp_obj
    #
    #     resp_obj['data'] = update_obj
    #     resp_obj['reset'] = reset_obj
    #     return resp_obj

    def get(self, request):
        try:
            Info('LOG', "My Profile")
            mobile = request._userInfo['mobile']
            lang = request.headers.get('language') or 'en'
            user_info = request._userInfo['record']
            remove_keys = ['profile_ext', 'tag_id']
            user_info = translatefields(user_info, lang)

            # construct profile img url
            if 'profile_pic' in user_info:
                mob_leading_chars = str(mobile)[:6]
                user_info['profile_url'] = PROFILE_URL_PREFIX + mob_leading_chars + '/'
                Info('LOG', f'Profile Pic URL of User: {user_info["profile_url"]}')

            # add tag info if tag is available
            if user_info.get('tag_id'):
                tag_id = user_info['tag_id']
                TAG_CACHE = get_valid_cache()
	
                tag_list = TAG_CACHE['tag_list']	
                target_tag = [tag for tag in tag_list if tag['id'] == tag_id][0]	
                	
                user_info['tag_info'] = {
                    'name'       : target_tag['lang'].get(lang, target_tag['name']),	
                    'id'         : tag_id,	
                    'url_prefix' : TAG_URL_PREFIX,	
                    "img_name"    : target_tag['img_name']	
                } 
                
            for key in remove_keys:	
                if key in user_info:	
                    del user_info[key]	
            return get_success_response(200, 2001, user_info)	
        except Exception as e:
            stack_trace = traceback.format_exc()
            Error('UNKNOWN_ERR', e.args[0], traceback=stack_trace)	
            return handle_exception(forward_exception(e, 'myProfile-get[view]'), request)

    def post(self, request):
        try:
            mobile = request._userInfo['mobile']
            update_data = request.POST
            update_files = request.FILES
            # return get_success_response(200, 2003, 'custom1')
            
            # validate request
            key_to_update = set(list(request.POST.keys()) + list(request.FILES.keys()))
            if not len(key_to_update):
                Error('INVALID_REQUEST','No Key/s to update profile!')
                return get_error_response(400, 4001, 'No Key/s to update!')

            if not key_to_update.issubset(UPDATE_KEYS):
                Error('INVALID_REQUEST','Unknown key/s for update profile!')
                return get_error_response(400, 4001, 'Unknown key/s for update!')
            
            resp = self.scan_data(update_data)
            if 'err' in resp:
                Error('UNKNOWN_ERR', f'error while scan data: {resp["err"]}')
                return get_error_response(*resp['err'])
            update_obj, reset_obj = resp['data'], resp['reset']

            # validate image as text data is clean
            if('profile_pic' in update_files):
                profile_obj = self.file_upload(mobile, update_files['profile_pic'])
                update_obj.update(profile_obj)

            user_info  = request._userInfo['record']
            user_id = user_info.pop('_id')

            # push to secondary mail if we've an old verified email of a user
            if 'email' in user_info and user_info.get('email_vrf') == 1 and user_info['email'] != update_obj.get('email'):
                sec_email = user_info.get("sec_email", [])
                sec_email.append(user_info['email'])
                sec_email = list(set(sec_email))

                Info('LOG', 'sec email of user', extra_data = {'sec_email': sec_email})
                update_obj['sec_email'] = sec_email

            # unset keys
            for item in reset_obj:
                if item in user_info:
                    del user_info[item]

            # send mail if new mail is found
            if 'email' in update_obj:
                if user_info.get('email') != update_obj['email']:
                    update_obj["email_vrf"] = 0
                    Info('LOG', 'Sending verification mail because new mail is found')
                    send_verification_email(update_obj['email'], mobile)
                elif user_info.get("email_vrf") == 0:
                    Info('LOG', 'Sending verification mail because new mail is found')
                    send_verification_email(update_obj['email'], mobile)

            # update new values
            for key in update_obj:
                if key in user_info:
                    if update_obj[key] != user_info[key]:
                        if key in TYPES:
                            type_data = {
                                            "ref": "tc.tc_2020",
                                            "t": TYPES[key],
                                            "src": "naam",
                                            "v": update_obj[key],
                                            "status": 0,
                                            "m": mobile,
                                            "ts": get_ts()
                                        }
                            es_insert(index = DETAILS_INDEX, doc = type_data)
                user_info[key] = update_obj[key]
            
            updatedRes = es_insert(index = USER_INDEX , doc = user_info , id = user_id)
            if(not updatedRes):
                Error('UNKNOWN_ERR',"Failed to update user-profile in elastic")
                return get_error_response(500, 5002)

            return get_success_response(200, 2003)
        except Exception as e:
            stack_trace = traceback.format_exc()
            Error('UNKNOWN_ERR', e.args[0], traceback=stack_trace)
            return handle_exception(forward_exception(e, 'myProfile-post[view]'), request)


class SetPincode(APIView):
   def get(self, request):
    try:
        if 'pincode' not in request.data:
            Error('INVALID_HEADERS','pincode not in request data')
            return get_error_response(400, 4002)

        pincode = request.data['pincode']
        if validate_otp(pincode):
            query = { "query": { "term": {"pincode": pincode }}, "size": 1 }
            data = es_search(PIN_INDEX, query, exclude_id=True)

            if not len(data):
                return get_success_response(200, 2008, None)
            
            res = {}
            for key in data[0]:
                res[key.lower()] = data[0][key]
                
            return get_success_response(200, 2001, res)
        else: 
            Error('INVALID_REQUEST',"Invalid pin entered!", extra_data = {'pincode':pincode})
            return get_error_response(400, 40010)
    except Exception as e:
        stack_trace = traceback.format_exc()
        Error('UNKNOWN_ERR', e.args[0], traceback=stack_trace)
        return handle_exception(forward_exception(e, 'setPincode[view]'), request)
   

class UserFeedback(APIView):
   def post(self, request):
    try:
        mobile = request._userInfo['mobile']

        if 'feedback' not in request.data:
            Error('INVALID_HEADERS', 'feedback not in req data')
            return get_error_response(400, 4002)

        feedback = request.data['feedback']
        if not isinstance(feedback, str):
            Error('INVALID_REQUEST', 'Feedback should be a valid text string!' )
            return get_error_response(400, 4001, "feedback should be a valid text string!")

        if (len(feedback) > 300):
            Error('INVALID_REQUEST', "Max feedback length should be less than 300 characters!")
            return get_error_response(429, 4293, "Max feedback length should be less than 300 characters!")
        
        f_obj = { 'feedback': feedback, 'mobile': mobile, 'created_dt': get_ts() }
        Info('LOG', f'UserFeedback: {f_obj}')
        es_insert(FEEDBACK_INDEX, f_obj)

        return get_success_response(200, 2001)
    except Exception as e:
        stack_trace = traceback.format_exc()
        Error('UNKNOWN_ERR', e.args[0], traceback=stack_trace)
        return handle_exception(forward_exception(e, 'userFeedback[view]'), request)


class Tags(APIView):	
    def get(self, request):	
        try:	
            data = get_valid_cache()	
            data_copy = deepcopy(data)	
            lang = request.headers.get('language') or 'en'	
            data_copy = translated_data(data_copy, lang)	
            return get_success_response(200, 2001, data_copy)	
        except Exception as e:	
            stack_trace = traceback.format_exc()
            Error('UNKNOWN_ERR', e.args[0], traceback=stack_trace)
            return handle_exception(forward_exception(e, 'tags[view]'), request)

class SendEmail(APIView):
    def get(self, request):
        try:
            mobile = request._userInfo['mobile']
            user_info  = request._userInfo['record']
            email = user_info.get("email", None)
            email_vrf = user_info.get("email_vrf", None)

            if email and not email_vrf:
                Info('LOG', 'Sending verification email', extra_data = {'mobile':mobile, 'email': email})
                mail_sent = send_verification_email(email, mobile)
                if mail_sent:
                    Info('LOG', f'Mail is sent to the email: {email}')
                    return get_success_response(200, 2004)
                else:
                    Error('MAIL_ERR', f'Error while sending email: {email}' )
                    return get_error_response(500, 5001)
            else:
                Error('INVALID_REQUEST')
                return get_error_response(400, 4001)
        except Exception as e:
            stack_trace = traceback.format_exc()
            Error('UNKNOWN_ERR', e.args[0], traceback=stack_trace)
            return handle_exception(forward_exception(e, 'sendEmail[view]'), request)


class VerifyEmail(APIView):
    def get(self,request,query):
        """
        From verification link, fetching the salt. Then finding it in database,
        If found, then change its  verification status as 1.
        """
        try:
            range_time = get_ts() - EMAIL_VERIFICATION_TTL * 60  # 30 mins before (30*60)

            salt_query = {
                "query": {
                    "bool": {
                        "filter": [
                            {"match": {"salt": str(query)}},
                            {"range": {"creation_time": {"gte": range_time}}}
                        ]
                    }
                }
            }

            try:
                search_result = es_search(EMAIL_VERIFY_INDEX, salt_query)
                if len(search_result) == 0:
                    Error('INVALID_REQUEST', "No Recent Email Request Found!" )
                    return get_error_response(400, 4012, "No Recent Email Request Found!")
                else:
                    email_info = search_result[0]
                    email_id = email_info['_id'] #this is not email_id, this is email's ID in email_verification index.
                    mobile = email_info['mobile']
                    email = email_info["email"]
                    Info('LOG','Search result of email verify index', extra_data = {'result':search_result})
                    
                    if email_info['status'] == 0:
                        es_update_by_id(EMAIL_VERIFY_INDEX, email_id, { 'status' : 1 })
                        searchQuery = {
                            "query": {
                                "bool": {
                                    "filter": [
                                        {"match": {"mobile": mobile}}
                                    ]
                                }
                            }
                        }

                        user_search_result = es_search(USER_INDEX, searchQuery)
                        user = user_search_result[0]
                        user_id = user["_id"]
                        primary_email = user["email"]
                        sec_email = user.get("sec_email", [])

                        # If this email is not in the sec_email field, add it to the list
                        if primary_email != email and email not in sec_email:
                            sec_email.append(primary_email)

                        try:
                            es_update_by_id(USER_INDEX, user_id, {"email_vrf": 1})
                        except Exception as e:
                            stack_trace = traceback.format_exc()
                            Error('UNKNOWN_ERR', f"While Upserting Email Vrf: {e.args[0]}", traceback=stack_trace)
                            return get_error_response(500, 5001)
                        return get_success_response(200, 2005)
                    else:
                        Error('INVALID_REQUEST', "email_info['status'] NOT equal to 0")
                        return get_error_response(401, 4014)
            except Exception as e:
                stack_trace = traceback.format_exc()
                Error('UNKNOWN_ERR', f"While Verify Email Token: {e.args[0]}", traceback=stack_trace)
                return get_error_response(500, 5001)
        except Exception as e:
            stack_trace = traceback.format_exc()
            Error('UNKNOWN_ERR', e.args[0], traceback=stack_trace)
            return handle_exception(forward_exception(e, 'VerifyEmail'), request)



class UserAppPermission(APIView):
   def post(self, request):
    try:
        mobile = request._userInfo['mobile']
    
        required_fields = ['call_logs', 'contacts', 'phone', 'caller_id', 'notification', 'disp_ovr_oth_app', 'app_v']

        if not all(field in request.data for field in required_fields):            
            Error('INVALID_HEADERS', 'Keys are missing!')
            return get_error_response(400, 4002)


        call_logs = request.data['call_logs']
        contacts = request.data['contacts']
        phone = request.data['phone']
        caller_id = request.data['caller_id']
        notification = request.data['notification']
        disp_ovr_oth_app = request.data['disp_ovr_oth_app']
        app_v = request.data['app_v']

        permission_obj = { 'call_logs': call_logs, 'contacts': contacts, 'phone':phone, 
            'caller_id':caller_id, 'notification':notification, 
            'disp_ovr_oth_app':disp_ovr_oth_app, 'app_v':app_v
        }

        Info('LOG','User app permission object', extra_data = permission_obj )

        # Search User permission already exists
        query = { "query": { "bool": { "must": [ {"match": {"mobile": mobile}} ] } } }
        search_result = es_search(USER_PERMISSION_INDEX, query)
        Info('LOG','Search result from user perimssion index', extra_data = {'result': search_result} )

        if len(search_result) == 0:
            permission_obj['creation_time'] = get_ts()
            permission_obj['mobile'] = mobile
            es_insert(USER_PERMISSION_INDEX, permission_obj)
            Info('LOG','User app permission object inserted')
            return get_success_response(200, 2001)
        else:
            user_per_id = search_result[0]['_id']
            permission_obj['updation_time'] = get_ts()
            es_update_by_id(USER_PERMISSION_INDEX, user_per_id, permission_obj)
            Info('LOG','User app permission object updated')
            return get_success_response(200, 2001)
            
    except Exception as e:
        stack_trace = traceback.format_exc()
        Error('UNKNOWN_ERR', e.args[0], traceback=stack_trace)
        return handle_exception(forward_exception(e, 'userPermission[view]'), request)
