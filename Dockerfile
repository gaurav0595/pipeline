FROM python:3.8-slim-bullseye

# Install SSH server
RUN apt-get update \
    && apt-get install -y openssh-server vim cron  git sudo supervisor \
    && rm -rf /var/lib/apt/lists/*

# Enabled SSH
RUN mkdir /var/run/sshd
RUN echo 'root:EP0021wqt' | chpasswd
RUN echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
RUN sed -i 's/PermitRootLogin without-password/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN echo 'ClientAliveInterval 300' >> /etc/ssh/sshd_config
#RUN echo 'ClientAliveCountMax 10' >> /etc/ssh/sshd_config
# SSH login fix. Otherwise user is kicked off after login
RUN sed 's@session\srequired\spam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd

# Setting Timezone-India
RUN ln -fs /usr/share/zoneinfo/Asia/Kolkata /etc/localtime

# Install required dependencies
RUN apt-get update \
    && apt-get install -y bash gcc libc-dev supervisor

# Coopy supervisord configuration
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf


# Copy application files
WORKDIR /app/naam-api-backend/api
#COPY requirements.txt .
#COPY requirements.txt /app/naam-api-backend/
COPY requirements.txt /app/

RUN pip3 install --upgrade pip
#RUN pip3 install -r /app/naam-api-backend/requirements.txt
RUN pip3 install -r /app/requirements.txt
COPY api /app/naam-api-backend/api


# Expose SSH and Python server port
EXPOSE 22
EXPOSE 8000
VOLUME /app

# Start supervisord as root
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]


# Server Environment
ENV SERVER_ENV=development

# Current Environment vairable
ENV CURR_ENV="Dev"

# Secret keys
ENV DJANGO_SECRET_KEY="2_tue8*dmh85qa8djprvr_zl*!^(ho8_wa(z@e(c4u_wdxo@5y"
ENV AES_SPK="GfZLlvlvmDXVdPVdxxhuEPAjUNZ5V8WU"
ENV AES_DAK="P2i0jUPLntONQl380tRFtTvg4xlRbkvE"
ENV AES_TEST_KEY="MWbpzsgcMQgJAtUYaPa7hDnNtlUGIHkF"
ENV JWT_SECRET_KEY="NtgC9zsLXj1qzA7w#$+RHKgfj461"

# M-Elastic
ENV M_ES_USER="USERNAME"
ENV M_ES_PASS="PASSWORD"
ENV M_ES_ENDPOINT_URL="https://api-dev-m-fastdb:0HUNWK2pHBittQ@api-dev-m.naam.ai:443"

# C-Elastic
ENV C_ES_USER="USERNAME"
ENV C_ES_PASS="PASSWORD"
ENV C_ES_ENDPOINT_URL="https://api-dev-c-fastdb:tGPVVmT648kopQ@api-dev-c-fastdb.naam.ai:443"


# Minio Creds
ENV MINIO_CONNECTION_ENDPOINT="obj.ajx.me:443"
ENV MINIO_CONNECTION_USER="naam-prod-zM6GsGH"
ENV MINIO_CONNECTION_PASSWORD="4Yk2tjl7ABEdKxpZrYCLQ9"


# Public URLs
ENV API_BASE_URL="https://api-dev.naam.ai/"
ENV API_SEARCH_URL="http://10.107.4.123:8000/"
ENV MINIO_BUCKET_URL="https://obj.ajx.me/"


## Rabbit MQ Credentials
ENV RABBITMQ_HOST="rabbitmq-naam-dev-0.rabbitmq-naam-dev-svc.naam-dev.svc.cluster.local"
ENV RABBITMQ_PORT=5672
ENV RABBITMQ_USER="noderabbit"
ENV RABBITMQ_PASS="BPUl223eRQmRP"


# Redis
ENV REDIS_HOST=redis-dev-0.redis-dev.naam-dev.svc.cluster.local
ENV REDIS_PORT=6379
