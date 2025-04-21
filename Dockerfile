FROM golang:alpine

ADD ./check-certs /

RUN chmod +x /check-certs \
    &&sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories \
    &&apk update \
    &&apk --no-cache add ca-certificates \
    &&rm -rf /var/apt/cache/*