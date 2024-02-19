FROM golang:1.21-alpine3.19

WORKDIR /src
COPY . /src
RUN go build

FROM alpine:3.19

COPY --from=0 /src/config-writer /config-writer

EXPOSE 3000
ENTRYPOINT /config-writer

USER 1001
