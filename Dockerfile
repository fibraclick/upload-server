FROM public.ecr.aws/m8i2k7g9/libvips-mozjpeg:c788f105e99835ce7bb1d2cb70637089c90c4b10

ENV DEBIAN_FRONTEND noninteractive

# Install Go
RUN wget https://golang.org/dl/go1.16.linux-amd64.tar.gz -O go.tar.gz && \
    tar -C /usr/local -xzf go.tar.gz

ENV GOROOT="/usr/local/go"
ENV GOPATH="/go"
ENV PATH="$GOROOT/bin:$PATH"

EXPOSE 8080

WORKDIR /go/projects/fibraclick-upload-server
COPY . .
RUN go install

CMD /go/bin/fibraclick-upload-server
