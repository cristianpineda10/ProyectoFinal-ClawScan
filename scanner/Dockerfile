FROM golang:1.27.3-alpine AS builder
RUN apk add --no-cache git ca-certificates
WORKDIR /src
RUN git clone --depth 1 https://github.com/openclaw/clawscan.git .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/clawscan ./cmd/clawscan

FROM alpine:3.22
RUN apk add --no-cache ca-certificates && addgroup -S clawscan && adduser -S -G clawscan clawscan
COPY --from=builder /out/clawscan /usr/local/bin/clawscan
USER clawscan
ENTRYPOINT ["clawscan"]
