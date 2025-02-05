FROM ubuntu:latest
LABEL authors="gaion"

ENTRYPOINT ["top", "-b"]