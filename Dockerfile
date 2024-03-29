FROM python:3

RUN apt update \
  && apt install -y default-jre-headless

ADD . /workspace

RUN python3 -m pip install -r /workspace/requirements.txt

WORKDIR /workspace

CMD ["python3", "central_system.py", "/certs"]
