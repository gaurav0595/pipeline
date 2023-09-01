import traceback, time, json, sys, os
from operator import itemgetter

from django.apps import AppConfig
from django.conf import settings
from django.core.signals import got_request_exception
from django.dispatch import receiver

from app.helper.commonFunction import send_mail
from app.model.elasticModel import es_search

from django.core.cache import cache


# Env variables
MINIO_BUCKET_URL = os.environ.get('MINIO_BUCKET_URL')
CURRENT_ENV = os.environ.get('CURR_ENV')


config = json.load(open('app/config/config.json'))

ES_INDICES       = config['data']['elastic']['indices']
TAGS_INDEX       = ES_INDICES['tags']
APP_BUCKET_URL   = MINIO_BUCKET_URL + config['data']['minio']['buckets']['app']
TAG_URL_PREFIX   = APP_BUCKET_URL + '/assets/tags/'

def get_tag_cache():
    query = {"query": {"match": {"type": "parent"}}, "size": 100}
    data = es_search(TAGS_INDEX, query)

    tag_list = []
    for tag_info in data:
        name, id, icon, iconType, lang = itemgetter('name', 'id', 'icon', 'iconType', 'lang')(tag_info)
        obj = {"name": name, "id": id, "img_name": icon + '.' + iconType, "lang": lang}
        tag_list.append(obj)

    data = {
        'tag_url_prefix': TAG_URL_PREFIX,
        'tag_list': tag_list,
    }

    settings.TAGS_CACHE.update({
        "data": data,
        "exp": time.time() + 86400
    })

    return settings.TAGS_CACHE

class NaamapiConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'app'

    def ready(self):

        TAG_CACHE = get_tag_cache()

        # this receiver will catch the server execption signal and then sending an email about it to the admins.
        @receiver(got_request_exception)
        def send_error_email(sender, request, **kwargs):
            exc_type, exc_value, tb = sys.exc_info()
            message = f'<div style="background:#e2e8f0;padding:10px;border-left:0.4em solid red"><b>Error::</b> {exc_value}<br/><b>Stack::</b> {traceback.format_tb(tb)}<br/></div>'
            recipient_list = [admin[1] for admin in settings.ADMINS]
            subject = f'Server Exception Occurred in Naam {CURRENT_ENV}'
            send_mail(subject, recipient_list, message)
