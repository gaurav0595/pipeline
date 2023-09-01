from app.helper.commonFunction import get_error_response
from app.helper.log_methods import Info, Error, Critical, Warn, SysLog


""" 
    Error Views
    @author: Govind Saini
    @updatedAt: 30th Nov'22
    @desc: custom error handlers for http codes
"""
def invalid_url(request, exception):
    Error('INVALID_URL', extra_data = {'result':request.path} )
    return get_error_response(404, 4042, "Invalid URL called!")
