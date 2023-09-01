from app.middleware.request import push_logs
import inspect
from time import time
from django.conf import settings
from .rabbitmq import RabbitMQHandler


def Info(*args, **kwargs):
    caller_frame = inspect.currentframe().f_back
    caller_filename = caller_frame.f_code.co_filename
    caller_function = caller_frame.f_code.co_name
    # caller_line_no = caller_frame.f_lineno

    kwargs['level'] = 'info'
    kwargs['module'] = caller_filename
    kwargs['function'] = caller_function
    push_logs(args, kwargs)


def Error(*args, **kwargs):
    caller_frame = inspect.currentframe().f_back
    caller_filename = caller_frame.f_code.co_filename
    caller_function = caller_frame.f_code.co_name

    kwargs['level'] = 'error'
    kwargs['module'] = caller_filename
    kwargs['function'] = caller_function
    push_logs(args, kwargs)


def Critical(*args, **kwargs):
    caller_frame = inspect.currentframe().f_back
    caller_filename = caller_frame.f_code.co_filename
    caller_function = caller_frame.f_code.co_name

    kwargs['level'] = 'critical'
    kwargs['module'] = caller_filename
    kwargs['function'] = caller_function
    push_logs(args, kwargs)


def Warn(*args, **kwargs):
    caller_frame = inspect.currentframe().f_back
    caller_filename = caller_frame.f_code.co_filename
    caller_function = caller_frame.f_code.co_name

    kwargs['level'] = 'warn'
    kwargs['module'] = caller_filename
    kwargs['function'] = caller_function
    push_logs(args, kwargs)


def SysLog(*args, **kwargs):
    caller_frame = inspect.currentframe().f_back
    caller_filename = ''.join((caller_frame.f_code.co_filename).split(str(settings.BASE_DIR)))
    caller_function = caller_frame.f_code.co_name
    # to be sent to queue
    log_obj = {
        "timestamp": int(time() * 1000),
        "level"    :  'syslog', # default level is syslog
        "tag"      : args[0] if len(args) else 'NO_TAG',
        "service"  : 'router/main',
        "module"   : caller_filename,
        "function" : caller_function,
    }

    if len(args) > 1: log_obj['message'] = args[1]
    if kwargs.get('extra_data', None): log_obj['extra_data'] = kwargs['extra_data']
    if kwargs.get('traceback', None): log_obj['traceback'] = kwargs['traceback']
    return RabbitMQHandler.push_logs_to_queue(log_obj, queue_name='internal_logs')


