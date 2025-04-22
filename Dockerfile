FROM golang:alpine as builder

ENV GOPROXY=https://mirrors.aliyun.com/goproxy/

ADD ./   /check-certs

RUN cd /check-certs \
    && go build check-certs.go

FROM golang:alpine

COPY --from=builder /check-certs /check-certs

RUN chmod +x /check-certs \
    && sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories \
    && apk update \
    && apk --no-cache add ca-certificates \
    && rm -rf /var/apt/cache/*