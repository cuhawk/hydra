// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package httpx

import (
	"context"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
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

// IsInternalIPExceptionURL reports whether targetURL matches any configured
// internal IP exception glob using the same URL normalization as the SSRF transport.
func IsInternalIPExceptionURL(targetURL *url.URL, exceptions []string) (bool, error) {
	if targetURL == nil || len(exceptions) == 0 {
		return false, nil
	}
	normalized := *targetURL
	normalized.RawQuery = ""
	normalized.RawFragment = ""
	candidate := normalized.String()
	for _, exception := range exceptions {
		compiled, err := glob.Compile(exception, '.', '/')
		if err != nil {
			return false, err
		}
		if compiled.Match(candidate) {
			return true, nil
		}
	}
	return false, nil
}

// RoundTrip implements http.RoundTripper.
func (n noInternalIPRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	allowed, err := IsInternalIPExceptionURL(IncomingRequestURL(request), n.internalIPExceptions)
	if err != nil {
		return nil, err
	}
	if allowed {
		return n.onWhitelist.RoundTrip(request)
	}

	return n.notOnWhitelist.RoundTrip(request)
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
