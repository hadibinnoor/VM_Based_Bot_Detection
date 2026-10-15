FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/bot-defense .

FROM alpine:3.21

WORKDIR /app

RUN adduser -D -H -u 10001 appuser

COPY --from=builder /out/bot-defense /app/bot-defense

EXPOSE 8080

USER appuser
ENTRYPOINT ["/app/bot-defense"]
