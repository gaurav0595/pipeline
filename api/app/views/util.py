import json, os
from rest_framework.views import APIView
from app.helper.commonFunction import get_success_response, get_error_response, validate_cc, handle_exception, forward_exception
from app.model.elasticModel import es_search

# read env
MINIO_BUCKET_URL = os.environ.get('MINIO_BUCKET_URL')

config = json.load(open('app/config/config.json'))
LANGDATA = config['templates']['langDetail']

#index/collection
stateIndex    = config['data']['elastic']['indices']['state']
cityIndex     = config['data']['elastic']['indices']['city']
COUNTRYINDEX  = config['data']['elastic']['indices']['cc']
APP_BUCKET_URL= MINIO_BUCKET_URL + config['data']['minio']['buckets']['app'] + '/'
TC_BUCKET     = MINIO_BUCKET_URL + config['data']['minio']['buckets']['tc'] + '/'


# API to get all states
class GetState(APIView):
   def get(self, request):
    try:
        query = { "query": { "match_all": {} }, "size": 100  }
        data = es_search(stateIndex,query)
        return get_success_response(200, 2001, data)
    except Exception as e:
        return handle_exception(forward_exception(e, 'getState[view]'), request)


# API to get all Cities
class GetCity(APIView):
   def get(self, request):
    try:

        if 'state_id' not in request.data:
            return get_error_response(400, 4002)

        user_data = request.data['state_id']

        if(user_data):
            state_id = user_data
            
            query = { "query": {"term": { "state_id": state_id}}, "size":10000 }
            data = es_search(cityIndex,query)

            if(len(data) == 0):
                return get_success_response(200, 2004, data, "No City Found!")
            return get_success_response(200, 2001, data)
        else:
            return get_error_response(400, 4002)
            
    except Exception as e:
        return handle_exception(forward_exception(e, 'getCity[view]'), request)


class SetLang(APIView):
    def post(self,request):
        try:
            if 'cc' not in request.data:
                return get_error_response(400, 4002)

            country_code = request.data['cc']

            langArr = []

            if(country_code == '+91'): 
                langArr = LANGDATA
            else: 
                langArr = [LANGDATA[0]]

            data = { "result": langArr, 'prefix': APP_BUCKET_URL }
            return get_success_response(200, 2001, data)
        except Exception as e:
            return handle_exception(forward_exception(e, 'setLang[view]'), request)


class SetLangImage(APIView):
  def post(self, request):
    try:

        if 'langCode' not in request.data:
            return get_error_response(400, 4002)

        langCode = request.data['langCode']

        for i in LANGDATA:
            for key in i:
                if(i[key] == langCode):
                    respData = {
                        'prefix': APP_BUCKET_URL,
                        # 'imgData': langImgArr
                    }
                    # enc = rsaEncrypt(respData)
                    return get_success_response(200, 2001, respData)

        else:
            return get_error_response(400, 4001, "Enter a Valid langCode!")
    except Exception as e:
        return handle_exception(forward_exception(e, 'setLangImage[view]'), request)


class GetCountry(APIView):
    def get(self, request):
        try:
            if 'cc' not in request.data:
                return get_error_response(400, 4002)

            country_code = request.data['cc']
            country_code = str(country_code)

            # Checking if Value exists
            if bool(country_code) == False:
                return get_error_response(400, 4001)

            cc = validate_cc(country_code)
            if bool(cc)==False:
                return get_error_response(400, 4001, "Enter Valid Country Code!")

            query = { "query": { "bool": { "must": [{ "match": { "ISD_code" : country_code }} ]} }}
            country_result = es_search(COUNTRYINDEX,query)

            if bool(country_result) == False:
                return get_success_response(200, 2001, {'country' : ""}, "No Country found!")
            else:
                country_result = country_result[0]['Country']
                res = { 'country': country_result }
                return get_success_response(200, 2001, res)

        except Exception as e:
            return handle_exception(forward_exception(e, 'getCountry[view]'), request)



