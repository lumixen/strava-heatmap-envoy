FROM golang:1.25.1 AS builder

WORKDIR /go/src/app
COPY go.mod go.sum main.go ./

RUN go mod download
RUN CGO_ENABLED=0 go build -o /go/bin/strava-heatmap-envoy

RUN apt-get update && apt-get install -y upx && upx --best /go/bin/strava-heatmap-envoy

FROM gcr.io/distroless/static-debian12
COPY --from=builder /go/bin/strava-heatmap-envoy /
CMD ["/strava-heatmap-envoy"]