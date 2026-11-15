FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN go build -o /diag .

FROM alpine:3.20
COPY --from=build /diag /diag
EXPOSE 9000
CMD ["/diag"]
