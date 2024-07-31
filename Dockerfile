FROM golang:1.21.3-alpine3.18 AS backend-builder

WORKDIR /build

COPY . .

ENV CGO_ENABLED=1 GOARCH=amd64 GOOS=linux GOPROXY=https://goproxy.cn,direct

RUN apk --no-cache add build-base &&\
    go mod download &&\
    go build -a -o wireguard-admin .

FROM node:20.12.2-alpine3.18 as frontend-builder

WORKDIR /build

COPY ui /build

RUN yarn &&\
    yarn build
    
FROM alpine:3.18

WORKDIR /app

COPY --from=backend-builder /build/wireguard-admin .
COPY --from=frontend-builder /build/dist ./public

RUN apk --no-cache add ca-certificates wireguard-tools iptables

ENTRYPOINT ["./wireguard-admin"]