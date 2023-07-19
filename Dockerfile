FROM golang:latest

RUN apt-get update \
    && apt-get install -y curl
RUN apt-get install -y libpcap-dev
RUN mkdir -p /go/src/app
WORKDIR /go/src/app
ADD . /go/src/app
RUN go get -v
RUN go get -t
RUN go test
RUN go build -o sniffer && mv sniffer /bin/sniffer
#CMD go test && go build -o app . && ./app
