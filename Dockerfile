FROM alpine:3.8
LABEL name="aws-es-proxy" version="latest"

RUN apk --no-cache add ca-certificates
WORKDIR /home/
COPY dist/linux/aws-es-proxy /usr/local/bin/

ENTRYPOINT ["aws-es-proxy"]
CMD ["-h"]
