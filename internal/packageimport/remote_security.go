package packageimport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

const remoteImportTimeout = 10 * time.Minute

var forbiddenRemoteNetworks = mustParseRemoteNetworks(
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"::/128",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
	"ff00::/8",
	"2001:db8::/32",
)

func mustParseRemoteNetworks(cidrs ...string) []*net.IPNet {
	networks := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}
		networks = append(networks, network)
	}
	return networks
}

func DefaultRemoteTargetValidator(ctx context.Context, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid remote URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("only HTTP(S) remote targets are allowed")
	}
	if u.Hostname() == "" {
		return errors.New("remote URL host is required")
	}
	return validateRemoteHost(ctx, u.Hostname())
}

func validateRemoteHost(ctx context.Context, hostname string) error {
	if ip := net.ParseIP(hostname); ip != nil {
		if isForbiddenRemoteIP(ip) {
			return fmt.Errorf("remote target %q resolves to a private or special address", hostname)
		}
		return nil
	}

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, hostname)
	if err != nil {
		return fmt.Errorf("resolve remote target %q: %w", hostname, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("remote target %q has no address", hostname)
	}
	for _, item := range ips {
		if isForbiddenRemoteIP(item.IP) {
			return fmt.Errorf("remote target %q resolves to a private or special address", hostname)
		}
	}
	return nil
}

func isForbiddenRemoteIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() {
		return true
	}
	for _, network := range forbiddenRemoteNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func newRemoteHTTPClient(validate func(context.Context, string) error) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	client := &http.Client{
		Transport: transport,
		Timeout:   remoteImportTimeout,
	}
	if validate == nil {
		return client
	}
	transport.DialContext = safeRemoteDialContext(validate)
	client.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		return validate(req.Context(), req.URL.String())
	}
	return client
}

func safeRemoteDialContext(validate func(context.Context, string) error) func(context.Context, string, string) (net.Conn, error) {
	dialer := &net.Dialer{}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		if err := validate(ctx, "https://"+net.JoinHostPort(host, port)); err != nil {
			return nil, err
		}

		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		for _, item := range ips {
			if isForbiddenRemoteIP(item.IP) {
				continue
			}
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(item.IP.String(), port))
			if err == nil {
				return conn, nil
			}
		}
		return nil, fmt.Errorf("unable to connect to allowed address for %s", host)
	}
}

func downloadRemoteArchive(ctx context.Context, source, artifactPath string, validate func(context.Context, string) error) error {
	if validate != nil {
		if err := validate(ctx, source); err != nil {
			return fmt.Errorf("validate remote package target: %w", err)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, remoteImportTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return fmt.Errorf("download remote package %q: %w", redactedRemoteArchiveSource(source), err)
	}
	resp, err := newRemoteHTTPClient(validate).Do(req)
	if err != nil {
		return fmt.Errorf("download remote package %q: %w", redactedRemoteArchiveSource(source), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("download remote package %q: HTTP %d", redactedRemoteArchiveSource(source), resp.StatusCode)
	}
	if err := os.MkdirAll(filepath.Dir(artifactPath), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(artifactPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, resp.Body)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}
