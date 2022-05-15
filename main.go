// Copyright (c) 2022 Cisco and/or its affiliates.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux
// +build linux

package main

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/google/uuid"

	"io/ioutil"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	nested "github.com/antonfisher/nested-logrus-formatter"
	"github.com/edwarnicke/grpcfd"
	"github.com/edwarnicke/vpphelper"
	"github.com/kelseyhightower/envconfig"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/networkservicemesh/api/pkg/api/ipam"
	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/cls"
	kernelsdk "github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/kernel"
	"github.com/networkservicemesh/api/pkg/api/networkservice/payload"
	registryapi "github.com/networkservicemesh/api/pkg/api/registry"
	"github.com/networkservicemesh/sdk/pkg/networkservice/chains/client"
	"github.com/networkservicemesh/sdk/pkg/networkservice/chains/endpoint"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/authorize"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms"
	kernel_sdk "github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms/kernel"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms/sendfd"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/retry"
	"github.com/networkservicemesh/sdk/pkg/networkservice/connectioncontext/ipcontext/vl3"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/adapters"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/chain"
	registryclient "github.com/networkservicemesh/sdk/pkg/registry/chains/client"
	"github.com/networkservicemesh/sdk/pkg/registry/common/dnsresolve"
	registrysendfd "github.com/networkservicemesh/sdk/pkg/registry/common/sendfd"
	"github.com/networkservicemesh/sdk/pkg/tools/debug"
	"github.com/networkservicemesh/sdk/pkg/tools/grpcutils"
	"github.com/networkservicemesh/sdk/pkg/tools/interdomain"
	"github.com/networkservicemesh/sdk/pkg/tools/log"
	"github.com/networkservicemesh/sdk/pkg/tools/log/logruslogger"
	"github.com/networkservicemesh/sdk/pkg/tools/spiffejwt"
	"github.com/networkservicemesh/sdk/pkg/tools/spire"
	"github.com/networkservicemesh/sdk/pkg/tools/token"
	"github.com/networkservicemesh/sdk/pkg/tools/tracing"

	"github.com/networkservicemesh/sdk-kernel/pkg/kernel/networkservice/connectioncontextkernel"
	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/connectioncontext/ipcontext/ipaddress"
	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/connectioncontext/ipcontext/routes"
	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/connectioncontext/ipcontext/unnumbered"
	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/connectioncontext/mtu"
	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/loopback"
	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/mechanisms/kernel"
	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/mechanisms/wireguard"
	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/tag"
	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/up"
	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/vrf"

	"github.com/networkservicemesh/cmd-nse-simple-vl3-docker/internal/spireconfig"
	"github.com/networkservicemesh/cmd-nse-simple-vl3-docker/vppinit"
)

// Config holds configuration parameters from environment variables
type Config struct {
	Name             string            `default:"docker-vl3-server" desc:"Name of vL3 Server"`
	RequestTimeout   time.Duration     `default:"15s" desc:"timeout to request NSE" split_words:"true"`
	ConnectTo        url.URL           `default:"tcp://k8s.nsm:5002" desc:"url to connect to" split_words:"true"`
	MaxTokenLifetime time.Duration     `default:"10m" desc:"maximum lifetime of tokens" split_words:"true"`
	ServiceNames     []string          `default:"docker-vl3" desc:"Name of providing service" split_words:"true"`
	Labels           map[string]string `default:"" desc:"Endpoint labels"`
	TunnelIP         net.IP            `desc:"IP to use for tunnels" split_words:"true"`
	Vl3Prefix        string            `default:"169.254.0.0/16" desc:"vl3 prefix"`
	InterfaceName    string            `default:"nsm" desc:"Name of the nsm network interface"`
	FederatesWith    string            `default:"k8s.nsm" desc:"Name of the federated domain"`
	TrustDomain      string            `default:"docker.nsm" desc:"Name of the trust domain"`
	LogLevel         string            `default:"INFO" desc:"Log level" split_words:"true"`
}

// Process prints and processes env to config
func (c *Config) Process() error {
	if err := envconfig.Usage("nsm", c); err != nil {
		return errors.Wrap(err, "cannot show usage of envconfig nse")
	}
	if err := envconfig.Process("nsm", c); err != nil {
		return errors.Wrap(err, "cannot process envconfig nse")
	}
	return nil
}

func startListenPrefixes(c *Config) <-chan *ipam.PrefixResponse {
	response := make(chan *ipam.PrefixResponse, 1)
	defer close(response)

	response <- &ipam.PrefixResponse{
		Prefix: c.Vl3Prefix,
	}
	return response
}

func main() {
	// ********************************************************************************
	// setup context to catch signals
	// ********************************************************************************
	ctx, cancel := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		// More Linux signals here
		syscall.SIGHUP,
		syscall.SIGTERM,
		syscall.SIGQUIT,
	)
	defer cancel()

	// ********************************************************************************
	// setup logging
	// ********************************************************************************
	log.EnableTracing(true)
	logrus.SetFormatter(&nested.Formatter{})
	ctx = log.WithLog(ctx, logruslogger.New(ctx, map[string]interface{}{"cmd": os.Args[0]}))

	if err := debug.Self(); err != nil {
		log.FromContext(ctx).Infof("%s", err)
	}

	starttime := time.Now()
	// enumerating phases
	log.FromContext(ctx).Infof("there are 7 phases which will be executed followed by a success message:")
	log.FromContext(ctx).Infof("the phases include:")
	log.FromContext(ctx).Infof("1: get config from environment")
	log.FromContext(ctx).Infof("2: run vpp and get a connection to it")
	log.FromContext(ctx).Infof("3: start spire-server and spire-agent")
	log.FromContext(ctx).Infof("4: retrieving svid, check spire agent logs if this is the last line you see")
	log.FromContext(ctx).Infof("5: create vl3-nse")
	log.FromContext(ctx).Infof("6: create nsc and do request to the vl3-nse")
	log.FromContext(ctx).Infof("7: register nse with nsm")
	log.FromContext(ctx).Infof("a final success message with start time duration")

	// ********************************************************************************
	log.FromContext(ctx).Infof("executing phase 1: get config from environment")
	// ********************************************************************************
	config := new(Config)
	if err := config.Process(); err != nil {
		log.FromContext(ctx).Fatal(err.Error())
	}
	log.FromContext(ctx).Infof("Config: %#v", config)

	level, err := logrus.ParseLevel(config.LogLevel)
	if err != nil {
		log.FromContext(ctx).Fatalf("invalid log level %s", config.LogLevel)
	}
	logrus.SetLevel(level)

	// ********************************************************************************
	log.FromContext(ctx).Infof("executing phase 2: run vpp and get a connection to it")
	// ********************************************************************************
	vppConn, vppErrCh := vpphelper.StartAndDialContext(ctx)
	exitOnErr(ctx, cancel, vppErrCh)

	defer func() {
		cancel()
		<-vppErrCh
	}()

	// ********************************************************************************
	log.FromContext(ctx).Info("executing phase 3: start spire-server and spire-agent")
	// ********************************************************************************
	spireRoot, err := ioutil.TempDir("", "spire")
	if err != nil {
		log.FromContext(ctx).Fatalf("error while creating spire root: %+v", err)
	}

	executable, err := os.Executable()
	if err != nil {
		log.FromContext(ctx).Fatalf("error while getting the app name: %+v", err)
	}
	spireChannel := spire.Start(
		spire.WithContext(ctx),
		spire.WithAgentID(fmt.Sprintf("spiffe://%s/agent", config.TrustDomain)),
		spire.WithAgentConfig(fmt.Sprintf(spireconfig.SpireAgentConfContents, spireRoot, config.TrustDomain)),
		spire.WithServerConfig(fmt.Sprintf(spireconfig.SpireServerConfContents, spireRoot, config.TrustDomain, config.FederatesWith, config.ConnectTo.Hostname())),
		spire.WithRoot(spireRoot),
		spire.WithFederatedEntry(fmt.Sprintf("spiffe://%s/%s", config.TrustDomain, filepath.Base(executable)),
			fmt.Sprintf("unix:path:%s", executable),
			fmt.Sprintf("spiffe://%s", config.FederatesWith),
		),
	)
	if len(spireChannel) != 0 {
		log.FromContext(ctx).Fatal(<-spireChannel)
	}

	// ********************************************************************************
	log.FromContext(ctx).Infof("executing phase 4: retrieving svid, check spire agent logs if this is the last line you see")
	// ********************************************************************************
	source, err := workloadapi.NewX509Source(ctx)
	if err != nil {
		log.FromContext(ctx).Fatalf("error getting x509 source: %+v", err)
	}

	svid, err := source.GetX509SVID()
	if err != nil {
		log.FromContext(ctx).Fatalf("error getting x509 svid: %+v", err)
	}
	log.FromContext(ctx).Infof("SVID: %q", svid.ID)

	tlsClientConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeAny())
	tlsClientConfig.MinVersion = tls.VersionTLS12

	// ********************************************************************************
	log.FromContext(ctx).Infof("executing phase 5: create vl3-nse")
	// ********************************************************************************
	listenOn := &(url.URL{Scheme: "tcp", Host: config.TunnelIP.String() + ":"})
	server := createVl3Endpoint(
		ctx,
		config,
		vppConn,
		vppinit.Must(vppinit.LinkToAfPacket(ctx, vppConn, config.TunnelIP)),
		source)

	srvErrCh := grpcutils.ListenAndServe(ctx, listenOn, server)
	exitOnErr(ctx, cancel, srvErrCh)
	log.FromContext(ctx).Infof("grpc server started")

	// ********************************************************************************
	log.FromContext(ctx).Infof("executing phase 6: create nsc and do request to the vl3-nse")
	// ********************************************************************************
	// We construct a client here and send Request to itself. Thus, we create an nsm interface for the monolith.
	// Since we are using vl3, all connected external clients will be on the same network.

	clientOptions := append(tracing.WithTracingDial(),
		grpcfd.WithChainStreamInterceptor(),
		grpcfd.WithChainUnaryInterceptor(),
		grpc.WithDefaultCallOptions(
			grpc.WaitForReady(true),
			grpc.PerRPCCredentials(token.NewPerRPCCredentials(spiffejwt.TokenGeneratorFunc(source, config.MaxTokenLifetime))),
		),
		grpc.WithTransportCredentials(
			grpcfd.TransportCredentials(
				credentials.NewTLS(tlsClientConfig),
			),
		),
	)

	dockerClient := createClient(ctx, listenOn, config.RequestTimeout, clientOptions...)
	for _, serviceName := range config.ServiceNames {
		// Construct a request
		request := &networkservice.NetworkServiceRequest{
			Connection: &networkservice.Connection{
				Id:             config.InterfaceName,
				NetworkService: interdomain.Target(serviceName),
				Payload:        payload.IP,
			},
			MechanismPreferences: []*networkservice.Mechanism{
				{Cls: cls.LOCAL, Type: kernelsdk.MECHANISM},
			},
		}
		var resp *networkservice.Connection
		resp, err = dockerClient.Request(ctx, request)
		if err != nil {
			log.FromContext(ctx).Errorf("request itself: %v", err)
		}
		defer func() {
			closeCtx, cancelClose := context.WithTimeout(ctx, config.RequestTimeout)
			defer cancelClose()
			_, _ = dockerClient.Close(closeCtx, resp)
		}()
	}

	// ********************************************************************************
	log.FromContext(ctx).Infof("executing phase 7: register nse with nsm")
	// ********************************************************************************
	nseRegistryClient := registryclient.NewNetworkServiceEndpointRegistryClient(
		ctx,
		registryclient.WithNSEClientURLResolver(dnsresolve.NewNetworkServiceEndpointRegistryClient()),
		registryclient.WithDialOptions(clientOptions...),
		registryclient.WithNSEAdditionalFunctionality(
			registrysendfd.NewNetworkServiceEndpointRegistryClient(),
		),
	)

	for _, serviceName := range config.ServiceNames {
		nsRegistryClient := registryclient.NewNetworkServiceRegistryClient(ctx,
			registryclient.WithNSClientURLResolver(dnsresolve.NewNetworkServiceRegistryClient()),
			registryclient.WithDialOptions(clientOptions...))

		_, err = nsRegistryClient.Register(ctx, &registryapi.NetworkService{
			Name:    serviceName,
			Payload: payload.IP,
		})
		if err != nil {
			log.FromContext(ctx).Fatalf("unable to register ns %+v", err)
		}
	}

	nseRegistration := &registryapi.NetworkServiceEndpoint{
		Name:                 config.Name,
		NetworkServiceNames:  config.ServiceNames,
		NetworkServiceLabels: make(map[string]*registryapi.NetworkServiceLabels),
		Url:                  listenOn.String(),
	}
	for _, serviceName := range config.ServiceNames {
		nseRegistration.NetworkServiceLabels[serviceName] = &registryapi.NetworkServiceLabels{Labels: config.Labels}
	}
	nseRegistration, err = nseRegistryClient.Register(ctx, nseRegistration)
	log.FromContext(ctx).Infof("registered nse: %+v", nseRegistration)

	if err != nil {
		log.FromContext(ctx).Fatalf("unable to register nse %+v", err)
	}

	log.FromContext(ctx).Infof("Startup completed in %v", time.Since(starttime))

	// wait for server to exit
	<-ctx.Done()
	<-vppErrCh
}

func createVl3Endpoint(ctx context.Context, config *Config, vppConn vpphelper.Connection, tunnelIP net.IP, source *workloadapi.X509Source) *grpc.Server {
	tlsServerConfig := tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeAny())
	tlsServerConfig.MinVersion = tls.VersionTLS12

	vl3Endpoint := endpoint.NewServer(ctx,
		spiffejwt.TokenGeneratorFunc(source, config.MaxTokenLifetime),
		endpoint.WithName(config.Name),
		endpoint.WithAuthorizeServer(authorize.NewServer()),
		endpoint.WithAdditionalFunctionality(
			vl3.NewServer(ctx, startListenPrefixes(config)),
			up.NewServer(ctx, vppConn, up.WithLoadSwIfIndex(loopback.Load)),
			ipaddress.NewServer(vppConn, ipaddress.WithLoadSwIfIndex(loopback.Load)),
			unnumbered.NewServer(vppConn, loopback.Load),
			vrf.NewServer(vppConn, vrf.WithLoadInterface(loopback.Load)),
			loopback.NewServer(vppConn),
			sendfd.NewServer(),
			up.NewServer(ctx, vppConn),
			mtu.NewServer(vppConn),
			routes.NewServer(vppConn),
			tag.NewServer(ctx, vppConn),
			mechanisms.NewServer(map[string]networkservice.NetworkServiceServer{
				wireguard.MECHANISM: wireguard.NewServer(vppConn, tunnelIP),
				kernel.MECHANISM:    kernel.NewServer(vppConn),
			}),
		),
	)

	gRPCOptions := append(
		tracing.WithTracing(),
		grpc.Creds(
			grpcfd.TransportCredentials(
				credentials.NewTLS(tlsServerConfig),
			),
		),
	)
	server := grpc.NewServer(gRPCOptions...)
	vl3Endpoint.Register(server)

	return server
}

func createClient(ctx context.Context, clientURL *url.URL, requestTimeout time.Duration, dialOptions ...grpc.DialOption) networkservice.NetworkServiceClient {
	name := "docker-client-" + uuid.New().String()
	dialTimeout := time.Millisecond * 200

	nsmClient := client.NewClient(ctx,
		client.WithClientURL(clientURL),
		client.WithName(name),
		client.WithAuthorizeClient(authorize.NewClient()),
		client.WithDialTimeout(dialTimeout),
		client.WithDialOptions(dialOptions...),
		client.WithAdditionalFunctionality(
			adapters.NewServerToClient(connectioncontextkernel.NewServer()),
			mechanisms.NewClient(map[string]networkservice.NetworkServiceClient{
				kernel.MECHANISM: chain.NewNetworkServiceClient(kernel_sdk.NewClient()),
			}),
		),
	)

	return retry.NewClient(nsmClient, retry.WithTryTimeout(requestTimeout))
}

func exitOnErr(ctx context.Context, cancel context.CancelFunc, errCh <-chan error) {
	// If we already have an error, log it and exit
	select {
	case err := <-errCh:
		log.FromContext(ctx).Fatal(err)
	default:
	}
	// Otherwise wait for an error in the background to log and cancel
	go func(ctx context.Context, errCh <-chan error) {
		err := <-errCh
		log.FromContext(ctx).Error(err)
		cancel()
	}(ctx, errCh)
}
