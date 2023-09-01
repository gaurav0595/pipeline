from django.utils.deprecation import MiddlewareMixin
from app.helper.logs_handler import LogsHandler
import uuid
from time import time

try:
    from threading import local
except ImportError:
    from django.utils._threading_local import local
    
_thread_locals = local()


def get_current_request():
    """ returns the request object for this thread """
    return getattr(_thread_locals, "request", None)

def push_logs(args, kwargs):
    """ push logs to request queue """
    _thread_locals.request_logs.append({ 'args': args, 'kwargs': kwargs })


class ThreadLocalMiddleware(MiddlewareMixin):
    """ adds the request object in thread local storage."""
    def process_request(self, request):
        request._request_id = str(uuid.uuid4())
        request._start_time = int(time() * 1000)
        _thread_locals.request_logs = []

    """ removes the request object from thread local storage."""
    def process_response(self, request, response):
        LogsHandler(_thread_locals.request_logs, request, response)
        
        if hasattr(_thread_locals, 'api_request_logs'):
            del _thread_locals.request_logs
        return response