import pika, environ, json, smtplib,os
from email.message import EmailMessage

config = json.load(open('app/config/config.json'))

# Current Env
CURRENT_ENV = os.environ.get('CURR_ENV')

# Rabbitmq Connection
RABBITMQ_HOST = os.environ.get('RABBITMQ_HOST')
RABBITMQ_PORT = os.environ.get('RABBITMQ_PORT')
RABBITMQ_USER = os.environ.get('RABBITMQ_USER')
RABBITMQ_PASS = os.environ.get('RABBITMQ_PASS')

# Email Credentials
EMAIL_FROM       = config['services']['email']['fromEmail']
EMAIL_USER       = config['services']['email']['user']
EMAIL_PASS       = config['services']['email']['pass']
EMAIL_URL        = config['services']['email']['url']
EMAIL_PORT       = config['services']['email']['port']


def send_mail(subject, content):
    try:
        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = EMAIL_FROM
        msg['To'] = ['mohit.a@sarv.com', 'jatin.s@sarv.com']

        msg.set_content(content, subtype='html')

        with smtplib.SMTP(EMAIL_URL, EMAIL_PORT) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.ehlo()
            smtp.login(EMAIL_USER, EMAIL_PASS) 
            smtp.send_message(msg)
            smtp.quit()
            return True
    except Exception as e:  
        raise Exception('UNKNOWN_ERR', { 'msg': f"send_mail: {e}" })



class RabbitMQClient:
    def __init__(self):
        self.connect()

    def connect(self):
        try:
            self.connection = pika.BlockingConnection(
                pika.ConnectionParameters(
                    host=RABBITMQ_HOST,
                    port=RABBITMQ_PORT,
                    credentials=pika.PlainCredentials(username=RABBITMQ_USER, password=RABBITMQ_PASS),
                    heartbeat=60
                )
            )
            self.channel = self.connection.channel()
            self.__declare_queue('api_request_logs')
            self.__declare_queue('internal_logs')
        except Exception as e:
            message = f'<div style="background:#e2e8f0;padding:10px;border-left:0.4em solid red"><b>Error::</b> "Rabbitmq connection lost " <br/><b>Stack::</b> <br/></div>'
            subject = f'Rabbitmq Connection Lost main in {CURRENT_ENV}'
            send_mail(subject, message) 


    def __declare_queue(self, queue_name):
        self.channel.queue_declare(queue=queue_name, durable=True)

    def push_logs_to_queue(self, log_message, queue_name='api_request_logs'):
        try:
            self.channel.basic_publish(
                exchange='',
                routing_key=queue_name,
                body=json.dumps(log_message),
                properties=pika.BasicProperties(
                        delivery_mode = pika.spec.PERSISTENT_DELIVERY_MODE,
                        expiration=str(config['settings']['rabbitmqTTL']),  # set the expiration time in milliseconds
                    )
            )

        except (pika.exceptions.AMQPError, pika.exceptions.StreamLostError) as e:
            # Reconnect and try again
            self.connect()
            return self.push_logs_to_queue(log_message, queue_name)

RabbitMQHandler = RabbitMQClient()
