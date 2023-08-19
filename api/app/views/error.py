from app.helper.commonFunction import get_error_response
from app.helper.logger import logger

""" 
    Error Views
    @author: Govind Saini
    @updatedAt: 30th Nov'22
    @desc: custom error handlers for http codes
"""
def invalid_url(request, exception):
    logger.info('Invalid url: %s', request.path)
    return get_error_response(404, 4042, "Invalid URL called!")
