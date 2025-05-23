ARG VPP_VERSION=v24.10.0-4-ga9d527a67
FROM ghcr.io/networkservicemesh/govpp/vpp:${VPP_VERSION} as go
COPY --from=golang:1.23.1 /usr/local/go/ /go
ENV PATH ${PATH}:/go/bin
ENV GO111MODULE=on
ENV CGO_ENABLED=0
ENV GOBIN=/bin
ARG BUILDARCH=amd64
RUN rm -r /etc/vpp
RUN go install github.com/go-delve/delve/cmd/dlv@v1.21.2
ADD https://github.com/spiffe/spire/releases/download/v1.10.3/spire-1.10.3-linux-${BUILDARCH}-musl.tar.gz .
ADD https://github.com/coredns/coredns/releases/download/v1.11.3/coredns_1.11.3_linux_${BUILDARCH}.tgz .
RUN tar xzvf spire-1.10.3-linux-${BUILDARCH}-musl.tar.gz -C /bin --strip=2 spire-1.10.3/bin/spire-server spire-1.10.3/bin/spire-agent
RUN tar xzvf coredns_1.11.3_linux_${BUILDARCH}.tgz -C /bin coredns

FROM go as build
WORKDIR /build
COPY go.mod go.sum ./
COPY ./local ./local
COPY ./internal/imports ./internal/imports
RUN go build ./internal/imports
COPY . .
RUN go build -o /bin/cmd-nse-simple-vl3-docker .

FROM build as test
CMD go test -test.v ./...

FROM test as debug
CMD dlv -l :40000 --headless=true --api-version=2 test -test.v ./...

FROM ghcr.io/networkservicemesh/govpp/vpp:${VPP_VERSION} as runtime
COPY --from=build /bin/cmd-nse-simple-vl3-docker /bin/cmd-nse-simple-vl3-docker
COPY --from=build /bin/spire-server /bin/spire-server
COPY --from=build /bin/spire-agent /bin/spire-agent
COPY --from=build /bin/coredns /bin/coredns
ENTRYPOINT [ "/bin/cmd-nse-simple-vl3-docker" ]
