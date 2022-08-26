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


FROM scratch

COPY --from=builder /dist/auth .

ENTRYPOINT [ "./auth", "run" ]
