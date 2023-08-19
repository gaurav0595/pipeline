import environ
from elasticsearch import Elasticsearch	

env = environ.Env()
M_ES_ENDPOINT_URL = env('M_ES_ENDPOINT_URL')
m_client = Elasticsearch(M_ES_ENDPOINT_URL)

C_ES_ENDPOINT_URL = env('C_ES_ENDPOINT_URL')
c_client = Elasticsearch(C_ES_ENDPOINT_URL)
es_clients = { 'm': m_client, 'c': c_client }


def es_search(index, query, raw_data=False, exclude_id=False, cluster='m'):
    try:
        filter_list = ['hits.hits._source']
        if not exclude_id:
            filter_list.append('hits.hits._id')

        filter_path = filter_list if not raw_data else None
        resp = es_clients[cluster].search(index=index, body=query, filter_path=filter_path)

        if not len(resp):
            return []
        if not raw_data:
            formatted_data = []

            for data in resp['hits']['hits']:
                dict = data['_source']
                if not exclude_id:
                    dict["_id"] = data['_id']
                formatted_data.append(dict)

            return formatted_data
        else:
            return resp['hits']['hits']
    except Exception as e:
        raise Exception('DB_SRCH_ERR', {'msg': f"es_search[E.M.]: {e}"})


def es_count(index, query, cluster='m'):
    try:
        resp = es_clients[cluster].count(index=index, body=query)
        return resp['count']
    except Exception as e:
        raise Exception('DB_COUNT_ERR', {'msg': f"es_count[E.M.]: {e}"})



def es_update_by_id(index, id, set_obj=None, script=None, cluster='m'):
    try:
        body = {"doc": set_obj} if not script else {"script": script}
        resp = es_clients[cluster].update(index=index, id=id, body=body)
        return resp['result']
    except Exception as e:
        raise Exception('DB_UPDATE_ERR', {'msg': f"es_update_by_id[E.M.]: {e}"})



def es_insert(index, doc, id=None, cluster='m'):
    try:
        resp = es_clients[cluster].index(index=index, id=id, document=doc)
        return resp['result']
    except Exception as e:
        raise Exception('DB_INS_ERR', {'msg': f"es_insert[E.M.]: {e}"})



def es_find_by_id(index, id, cluster='m'):
    try:
        resp = es_clients[cluster].get(index=index, id=id)
        return resp
    except Exception as e:
        print('ID excp:', e)
        raise Exception('DB_SRCH_ERR', {'msg': f"es_find_by_id[E.M.]: {e}"})



def es_delete_by_id(index, id, cluster='m'):
    try:
        resp = es_clients[cluster].delete(index=index, id=id)
        return resp['result']
    except Exception as e:
        raise Exception('DB_DEL_ERR', {'msg': f"es_delete_by_id[E.M.]: {e}"})




