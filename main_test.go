// Copyright (c) 2022-2023 Cisco and/or its affiliates.
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

package main_test

import (
	"context"
	"net/url"
	"os"
	"testing"

	main "github.com/networkservicemesh/cmd-nse-simple-vl3-docker"
	"github.com/networkservicemesh/sdk/pkg/tools/sandbox"
	"github.com/stretchr/testify/require"
)

func TestEndpointRegister(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const RegisterAsURL = "tcp://10.10.10.10:10101"

	dnsServer := sandbox.NewFakeResolver()
	domain := sandbox.NewBuilder(ctx, t).SetDNSResolver(dnsServer).Build()
	require.NoError(t, sandbox.AddSRVEntry(dnsServer, "nsm-system.", "registry", domain.Registry.URL))
	listenOn := &(url.URL{Scheme: "tcp", Host: "127.0.0.1:"})
	os.Setenv("NSM_REGISTER_AS_URL", RegisterAsURL)
	os.Setenv("NSM_REGISTRY_CLIENT_POLICIES", "")
	config := new(main.Config)
	err := config.Process()
	require.Nil(t, err)

	nseRegistration, err := main.RegisterNetworkServiceEndpoint(ctx, config, dnsServer, listenOn, sandbox.DialOptions())
	require.Nil(t, err)
	require.NotNil(t, nseRegistration)
	require.Equal(t, nseRegistration.Url, RegisterAsURL)
}
