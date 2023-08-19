from minio import Minio
import json
import environ
env = environ.Env()	
MINIO_CONNECTION_ENDPOINT = env('MINIO_CONNECTION_ENDPOINT')	
MINIO_CONNECTION_USER = env('MINIO_CONNECTION_USER')	
MINIO_CONNECTION_PASSWORD = env('MINIO_CONNECTION_PASSWORD')	

minio_client = Minio( 
    MINIO_CONNECTION_ENDPOINT,
    access_key = MINIO_CONNECTION_USER,
    secret_key = MINIO_CONNECTION_PASSWORD,
    secure = True 
)