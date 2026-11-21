// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package httpx

import (
	"context"
	"net"
	"net/http"
	"net/http/httptrace"
	"time"

	"github.com/gobwas/glob"
	"go.opentelemetry.io/contrib/instrumentation/net/http/httptrace/otelhttptrace"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/ory/x/ipx"
)

var _ http.RoundTripper = (*noInternalIPRoundTripper)(nil)

type noInternalIPRoundTripper struct {
	onWhitelist, notOnWhitelist http.RoundTripper
	internalIPExceptions        []string
}

// RoundTrip implements http.RoundTripper.
func (n noInternalIPRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	matches, err := MatchesInternalIPException(request, n.internalIPExceptions)
	if err != nil {
		return nil, err
	}
	if matches {
		return n.onWhitelist.RoundTrip(request)
	}

	return n.notOnWhitelist.RoundTrip(request)
}

// MatchesInternalIPException reports whether the request URL matches an internal IP exception.
func MatchesInternalIPException(request *http.Request, exceptions []string) (bool, error) {
	incoming := IncomingRequestURL(request)
	incoming.RawQuery = ""
	incoming.RawFragment = ""
	for _, exception := range exceptions {
		compiled, err := glob.Compile(exception, '.', '/')
		if err != nil {
			return false, err
		}
		if compiled.Match(incoming.String()) {
			return true, nil
		}
	}

	return false, nil
}

var (
	prohibitInternalAllowIPv6 http.RoundTripper = OTELTraceTransport(ssrfTransport(ipx.ProhibitInternalDialFunc))
	allowInternalAllowIPv6    http.RoundTripper = OTELTraceTransport(ssrfTransport(ipx.AllowInternalDialFunc))
)

func ssrfTransport(dial func(ctx context.Context, network, address string) (net.Conn, error)) *http.Transport {
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dial,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// OTELTraceTransport wraps the given http.Transport with OpenTelemetry instrumentation.
func OTELTraceTransport(t *http.Transport) http.RoundTripper {
	return otelhttp.NewTransport(t, otelhttp.WithClientTrace(func(ctx context.Context) *httptrace.ClientTrace {
		return otelhttptrace.NewClientTrace(ctx, otelhttptrace.WithoutHeaders(), otelhttptrace.WithoutSubSpans())
	}))
}
