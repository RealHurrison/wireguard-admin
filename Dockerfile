FROM golang:1.21.3-alpine3.18 AS backend-builder-base-compiler

RUN apk --no-cache add build-base

FROM backend-builder-base-compiler AS backend-builder-base

WORKDIR /build

COPY go.mod go.sum ./

RUN go mod download

FROM backend-builder-base AS backend-builder

WORKDIR /build

COPY . .

ENV CGO_ENABLED=1 GOARCH=amd64 GOOS=linux

RUN go build -o wireguard-admin .

FROM node:20.12.2-alpine3.18 as frontend-builder

WORKDIR /build

COPY ui /build

RUN yarn &&\
    yarn build
    
FROM alpine:3.18 as base

RUN apk --no-cache add ca-certificates wireguard-tools iptables &&\
    rm -rf /var/cache/apk/*

FROM base

WORKDIR /app

COPY --from=backend-builder /build/wireguard-admin .
COPY --from=frontend-builder /build/dist ./public

ENTRYPOINT ["./wireguard-admin"]