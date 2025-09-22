# temp stage
FROM python:3-slim-bullseye as builder

# avoid stuck build due to user prompt
ARG DEBIAN_FRONTEND=noninteractive
ARG TEST=TEST

RUN apt-get update && apt-get upgrade -y

# create and activate virtual environment
# using final folder name to avoid path issues with packages
RUN mkdir /opt/app
RUN python3 -m venv /opt/app/.venv
ENV PATH="/opt/app/.venv/bin:$PATH"

# install requirements
COPY requirements.txt .
RUN pip3 install --upgrade pip && pip3 install --no-cache-dir wheel && pip3 install --no-cache-dir -r requirements.txt


##############################################################################################
FROM python:3-slim-bullseye as runtime

RUN apt-get update && apt-get upgrade -y && apt-get install -y gosu libnatpmp-dev

COPY --from=builder /opt/app /opt/app

# make sure all messages always reach console

ENV PATH="/opt/app/.venv/bin:$PATH"
ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONFAULTHANDLER 1
ENV PYTHONUNBUFFERED 1


# activate virtual environment
ENV VIRTUAL_ENV="/opt/app/.venv"

WORKDIR /opt/app
COPY run.py run.py

COPY ./entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT [ "/entrypoint.sh" ]
CMD [ "python3", "run.py" ]
# VOLUME [ "/reports" ]
