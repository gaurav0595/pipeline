#FROM python:3.8-alpine3.16
FROM python:3.8-slim-bullseye
#ddFROM python:3.8-slim-buster 
#RUN apk --update add --no-cache bash gcc libc-dev 
RUN apt update && apt  install -y   bash gcc libc-dev 

#S
#RUN apk add tzdata
#RUN apt install tzdata
RUN cp /usr/share/zoneinfo/Asia/Kolkata /etc/localtime

COPY requirements.txt /app/requirements.txt
RUN pip3 install --upgrade pip
# Switch to use a non-root user from here on
USER root


# Add application
WORKDIR /app
RUN pip3 install -r requirements.txt
COPY api /app
CMD ["python3", "manage.py", "runserver", "0.0.0.0:8000"]
