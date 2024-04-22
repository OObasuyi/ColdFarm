FROM --platform=linux/amd64 python:3.11-slim AS x86_64_image

LABEL authors="Osamuede Obasuyi"
LABEL description="This image contains a portable version of ColdFarm."
LABEL version="1.0"
LABEL license="GPL"


COPY . /ColdFarm
WORKDIR /ColdFarm


RUN pip install -r requirements.txt


CMD ["python3.11", "./term_access.py", "--config_file", "config.yaml"]