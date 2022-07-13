FROM python:3.8.3-alpine
# 파이썬 환경 변수 설정
ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1

# 컨테이너내 작업 디렉토리 생성
RUN mkdir /home/app
WORKDIR /home/app

# dependencies를 위한 apt-get update
RUN apk update \
    && apk add --virtual build-deps gcc python3-dev musl-dev \
    && apk add postgresql-dev gcc python3-dev musl-dev \
    && apk add jpeg-dev zlib-dev freetype-dev lcms2-dev openjpeg-dev tiff-dev tk-dev tcl-dev \
    && apk del build-deps \
    && apk --no-cache add musl-dev linux-headers g++ tzdata

# install dependencies
RUN pip install --upgrade pip
ADD requirements.txt /home/app/ 
RUN pip install -r requirements.txt

# Copy(add) project files
ADD . /home/app/
