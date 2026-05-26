# build stage
FROM golang:alpine AS build-env
RUN apk --no-cache add build-base git gcc
ADD . /src
RUN cd /src && go build -v -ldflags "-s -w" -o slider .

# final stage
FROM alpine
WORKDIR /app
COPY --from=build-env /src/slider /app/
ENTRYPOINT ["./slider"]
