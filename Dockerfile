FROM golang:1.25.1 AS builder

WORKDIR /go/src/app
COPY go.mod go.sum main.go ./

RUN go mod download
RUN CGO_ENABLED=0 go build -o /go/bin/app

RUN apt-get update && apt-get install -y upx && upx --best /go/bin/app

FROM gcr.io/distroless/static-debian12
COPY --from=builder /go/bin/app /
CMD ["/app"]