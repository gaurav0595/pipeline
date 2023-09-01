from time import time
from django.conf import settings
from .rabbitmq import RabbitMQHandler
import json
import datetime
import pytz

from django.core.cache import cache


itc = pytz.timezone('Asia/Kolkata')





LOG_TYPE_SHORTHAND = [
    'API_SUCCESS',
    'TOKEN_ERR',
    'TOKEN_EXP',
    'INVALID_ENC',
    'INVALID_HEADERS',
    'INVALID_REQUEST',
    'INVALID_URL',
    'ES_COUNT_ERR',
    'ES_SRCH_ERR',
    'ES_UPDATE_ERR',
    'ES_INS_ERR',
    'ES_DEL_ERR',
    'UNKNOWN_ERR',
    'MINIO_ERR',
    'REDIS_ERR',
    'RABBITMQ_PUSH_ERR',
    'MAIL_ERR',
    'SMS_ERR',
    'TRANSLATION_ERR',
    'PARTIAL_DATA',
    'USER_LIMIT_REACHED',
    'SERVICE_UNAVAILABLE',
    'GATEWAY_TIMEOUT',
    'TAG_CACHE_ERR',
    'WRONG_OTP',
    'TEMPORARY_BLOCKED',
    'LOGIN_REQUEST_TIMEOUT',
    'LOG'
]


class LogsHandler:
    def __init__(self, api_logs, request, response=None):
        self.request = request
        self.response = response
        self.api_logs = api_logs
        self.request_id = request._request_id
        self.request_start_time = request._start_time
        self.request_logs = []
        self.matrix_log = None

        self.__create_logs()
        self.__create_api_matrix()
        self.__push_to_queue()

    def __create_logs(self):
        try:
            error_occurred = False

            for log in self.api_logs:
                args, kwargs = log['args'], log['kwargs']

                if kwargs.get('level', 'info') == 'error':
                    if error_occurred:
                        continue
                    error_occurred = True

                args_len = len(args)

                log_obj = {
                    "timestamp": int(time() * 1000),
                    # default level is info
                    "level": kwargs.get('level', 'info'),
                    "tag": args[0] if len(args) else 'NO_TAG',
                    "req_id": self.request_id,
                    "service": 'router/main',
                    "request": {
                        "method": self.request.method,
                        "path": self.request.path,
                        "ip": self.__get_ip()
                    }
                }

    
                updated_debug_logs_value = cache.get('DEBUG_LOGS')
                if kwargs.get('level') == 'info':
                    if updated_debug_logs_value == "True":
                        if len(cache.get('DEBUG_FILTER')) == 0:
                            log_obj['INFO_FOR_ALL'] = True
                        else:
                            if self.__check_if_debug_user():
                                log_obj['DEBUG_FILTER'] = cache.get('DEBUG_FILTER')
                            else:
                                continue
                    else:
                        continue


                if args_len and (args[0] not in LOG_TYPE_SHORTHAND):
                    log_obj['custom'] = True

                if args_len > 1:
                    log_obj['message'] = args[1]

                if getattr(self.request, '_userInfo', None):
                    log_obj['user'] = {
                        'mobile': self.request._userInfo['mobile']}
                    if self.request._userInfo.get('user_id', None):
                        log_obj['user']['user_id'] = self.request._userInfo['user_id']

                if kwargs.get('extra_data', None):
                    log_obj['extra_data'] = kwargs['extra_data']
                if kwargs.get('module', None):
                    log_obj['module'] = ''.join(
                        kwargs['module'].split(str(settings.BASE_DIR)))
                if kwargs.get('function', None):
                    log_obj['function'] = kwargs['function']
                if kwargs.get('traceback', None):
                    log_obj['traceback'] = kwargs['traceback']

                #'--------------------------Log Obj--------------------------------------'
                self.request_logs.append(log_obj)

        except Exception as e:
            # send mail in this case
            raise e

    def __get_ip(self):
        return self.request.META.get('HTTP_X_FORWARDED_FOR') or \
            self.request.META.get('HTTP_X_REAL_IP') or \
            self.request.META.get('REMOTE_ADDR') or \
            self.request.META.get('HTTP_CLIENT_IP')

    def __create_api_matrix(self):
        current_time = int(time() * 1000)

        api_matrix = {
            "status": self.response.status_code,
            "request_time": self.request_start_time,
            "response_time": current_time,
            "duration":  str(current_time - self.request_start_time) + 'ms',
            "method": self.request.method,
            "path": self.request.path,
            "req_id": self.request_id,
            "module": "router/main"
        }

        # '--------------------------api_matrix--------------------------------------'
        self.matrix_log = api_matrix

    # def __add_debug_info(self, log_obj):
    #     is_debug_user = self.__check_if_debug_user()
    #     current_time = int(time() * 1000)

    #     if is_debug_user:
    #         if settings.DEBUG_FILTER:
    #             debug_filter = settings.DEBUG_FILTER
    #             log_obj['debug_filter'] = debug_filter

    #         log_obj['request']['body'] = self.request.body.decode("utf-8")
    #         log_obj['request']['time'] = self.request_start_time
    #         log_obj['request']['headers'] = self.request.headers
    #         log_obj['response'] = {
    #             "status": self.response.status_code,
    #             "body": json.loads(self.response.content.decode("utf-8")),
    #             "duration":  (current_time - self.request_start_time),
    #             "time": current_time
    #         }


    def __check_if_debug_user(self):
        if not getattr(self.request, '_userInfo', None) or not cache.get('DEBUG_FILTER'):
            return False

        user_info = self.request._userInfo
        debug_filter = cache.get('DEBUG_FILTER')

        for key, value in debug_filter.items():
            if not user_info.get(key, None) or user_info[key] not in value:
                return False
        return True

    def __push_to_queue(self):
        if self.matrix_log:
            RabbitMQHandler.push_logs_to_queue(
                self.matrix_log, queue_name='api_request_logs')
        if len(self.request_logs):
            #'--------------------------Log--------------------------------------'
            RabbitMQHandler.push_logs_to_queue(self.request_logs, queue_name='internal_logs')















"""
custom response and request data for debugging []
Log Schema
{
    "tag": "LOG_TYPE_SHORTHAND",
    "custom": true,
    "req_id": "user_id:req_start_time", // ???
    "timestamp": "TIMESTAMP", // for debugging and visual representations
    "message": "LOG_MESSAGE", // actual msg for that particular log
    "level": "LOG_LEVEL", // info, warn, err, debug, critical
    "service": "SERVICE_NAME", // router/main OR search - configurable once at api server initialization
    "module": "MODULE_NAME", // optional
    "function": "FUNCTION_NAME", // optional if needed
    "traceback": "TRACEBACK_DETAILS", // in case of err tracing,
    "request": {// when debugging Is on
                "method": "REQUEST_METHOD",
                "path": "REQUEST_PATH",
                "query_params": "QUERY_PARAMETERS_ONLY_IF_NEEDED",
                "body": "REQUEST_BODY_ONLY_IF_NEEDED"
                },
    "response": {// when debugging Is on
                "status": "RESPONSE_STATUS",
                "body": "RESPONSE_BODY_ONLY_IF_NEEDED",
                "duration": "RESPONSE_TIME_ONLY_IF_NEEDED"
                },
    "user": {
    "id": "USER_ID",
    "mobile": "USER_MOBILE",
    // "token": "USER_TOKEN"
},
    "extra_data": {} // mapping should be on {enabled: false} if we want to add same keys at different times or different data-types according to the purpose
}
"""
