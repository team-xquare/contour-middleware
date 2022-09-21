FROM golang:alpine AS builder 

ENV GO111MODULE=on\
    CGO_ENABLED=0\
    GOOS=linux \
    GOARCH=amd64 

WORKDIR /build

COPY go.mod go.sum main.go ./

RUN go mod download

COPY . ./

RUN go build -o auth .

WORKDIR /dist

RUN cp /build/auth .


FROM alpine

COPY --from=builder /dist/auth .

RUN apk update && apk add --no-cache shadow && chsh -s /bin/bashx

ARG JWT_SECRET
ARG SENTRY_DS

ENV JWT_SECRET ${JWT_SECRET}
ENV SENTRY_DSN ${SENTRY_DSN}

ENTRYPOINT [ "./auth", "run" ]
