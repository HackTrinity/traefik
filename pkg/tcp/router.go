package tcp

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/containous/traefik/v2/pkg/log"
	"github.com/gravitational/trace"
)

// Router is a TCP router
type Router struct {
	routingTable        map[string]Handler
	connectRoutingTable map[string]Handler
	httpForwarder       Handler
	httpsForwarder      Handler
	httpHandler         http.Handler
	httpsHandler        http.Handler
	httpsTLSConfig      *tls.Config // default TLS config
	catchAll            Handler
	hostHTTPTLSConfig   map[string]*tls.Config // TLS configs keyed by SNI
}

// ServeTCP forwards the connection to the right TCP/HTTP handler
func (r *Router) ServeTCP(conn WriteCloser) {
	// FIXME -- Check if ProxyProtocol changes the first bytes of the request

	if r.catchAll != nil && len(r.routingTable) == 0 && len(r.connectRoutingTable) == 0 {
		r.catchAll.ServeTCP(conn)
		return
	}

	br := bufio.NewReader(conn)
	serverName, tls, peeked, err := clientHelloServerName(br)
	if err != nil {
		conn.Close()
		return
	}

	// Remove read/write deadline and delegate this to underlying tcp server (for now only handled by HTTP Server)
	err = conn.SetReadDeadline(time.Time{})
	if err != nil {
		log.WithoutContext().Errorf("Error while setting read deadline: %v", err)
	}

	err = conn.SetWriteDeadline(time.Time{})
	if err != nil {
		log.WithoutContext().Errorf("Error while setting write deadline: %v", err)
	}

	if !tls {
		host, connect, peeked, err := httpConnectHost(br)
		if err != nil {
			conn.Close()
			return
		}

		if !connect {
			switch {
			case r.catchAll != nil:
				r.catchAll.ServeTCP(r.GetConn(conn, peeked))
			case r.httpForwarder != nil:
				r.httpForwarder.ServeTCP(r.GetConn(conn, peeked))
			default:
				conn.Close()
			}
			return
		}

		host = strings.ToLower(host)
		if r.connectRoutingTable != nil {
			if target, ok := r.connectRoutingTable[host]; ok {
				target.ServeTCP(r.GetConn(conn, peeked))
				return
			}
		}

		// FIXME Needs tests
		if target, ok := r.connectRoutingTable["*"]; ok {
			target.ServeTCP(r.GetConn(conn, peeked))
			return
		}

		conn.Close()
		return
	}

	// FIXME Optimize and test the routing table before helloServerName
	serverName = strings.ToLower(serverName)
	if r.routingTable != nil && serverName != "" {
		if target, ok := r.routingTable[serverName]; ok {
			target.ServeTCP(r.GetConn(conn, peeked))
			return
		}
	}

	// FIXME Needs tests
	if target, ok := r.routingTable["*"]; ok {
		target.ServeTCP(r.GetConn(conn, peeked))
		return
	}

	if r.httpsForwarder != nil {
		r.httpsForwarder.ServeTCP(r.GetConn(conn, peeked))
	} else {
		conn.Close()
	}
}

// AddPassthroughRoute defines a handler for a given sniHost
func (r *Router) AddPassthroughRoute(sniHost string, target Handler) {
	if r.routingTable == nil {
		r.routingTable = map[string]Handler{}
	}
	r.routingTable[strings.ToLower(sniHost)] = target
}

// AddRouteTLS defines a handler for a given sniHost and sets the matching tlsConfig
func (r *Router) AddRouteTLS(sniHost string, target Handler, config *tls.Config) {
	r.AddPassthroughRoute(sniHost, &TLSHandler{
		Next:   target,
		Config: config,
	})
}

// AddRouteHTTPTLS defines a handler for a given sniHost and sets the matching tlsConfig
func (r *Router) AddRouteHTTPTLS(sniHost string, config *tls.Config) {
	if r.hostHTTPTLSConfig == nil {
		r.hostHTTPTLSConfig = map[string]*tls.Config{}
	}
	r.hostHTTPTLSConfig[sniHost] = config
}

// AddRouteHTTPConnect defines a handler for a given connectHost
func (r *Router) AddRouteHTTPConnect(connectHost string, target Handler) {
	if r.connectRoutingTable == nil {
		r.connectRoutingTable = map[string]Handler{}
	}
	r.connectRoutingTable[strings.ToLower(connectHost)] = target
}

// AddCatchAll defines the fallback tcp handler
func (r *Router) AddCatchAll(handler Handler) error {
	if r.catchAll != nil {
		return trace.AlreadyExists("catch all route already set")
	}

	r.catchAll = handler
	return nil
}

// GetConn creates a connection proxy with a peeked string
func (r *Router) GetConn(conn WriteCloser, peeked string) WriteCloser {
	// FIXME should it really be on Router ?
	conn = &Conn{
		Peeked:      []byte(peeked),
		WriteCloser: conn,
	}
	return conn
}

// GetHTTPHandler gets the attached http handler
func (r *Router) GetHTTPHandler() http.Handler {
	return r.httpHandler
}

// GetHTTPSHandler gets the attached https handler
func (r *Router) GetHTTPSHandler() http.Handler {
	return r.httpsHandler
}

// HTTPForwarder sets the tcp handler that will forward the connections to an http handler
func (r *Router) HTTPForwarder(handler Handler) {
	r.httpForwarder = handler
}

// HTTPSForwarder sets the tcp handler that will forward the TLS connections to an http handler
func (r *Router) HTTPSForwarder(handler Handler) {
	for sniHost, tlsConf := range r.hostHTTPTLSConfig {
		r.AddRouteTLS(sniHost, handler, tlsConf)
	}

	r.httpsForwarder = &TLSHandler{
		Next:   handler,
		Config: r.httpsTLSConfig,
	}
}

// HTTPHandler attaches http handlers on the router
func (r *Router) HTTPHandler(handler http.Handler) {
	r.httpHandler = handler
}

// HTTPSHandler attaches https handlers on the router
func (r *Router) HTTPSHandler(handler http.Handler, config *tls.Config) {
	r.httpsHandler = handler
	r.httpsTLSConfig = config
}

// Conn is a connection proxy that handles Peeked bytes
type Conn struct {
	// Peeked are the bytes that have been read from Conn for the
	// purposes of route matching, but have not yet been consumed
	// by Read calls. It set to nil by Read when fully consumed.
	Peeked []byte

	// Conn is the underlying connection.
	// It can be type asserted against *net.TCPConn or other types
	// as needed. It should not be read from directly unless
	// Peeked is nil.
	WriteCloser
}

// Read reads bytes from the connection (using the buffer prior to actually reading)
func (c *Conn) Read(p []byte) (n int, err error) {
	if len(c.Peeked) > 0 {
		n = copy(p, c.Peeked)
		c.Peeked = c.Peeked[n:]
		if len(c.Peeked) == 0 {
			c.Peeked = nil
		}
		return n, nil
	}
	return c.WriteCloser.Read(p)
}

func httpConnectHost(br *bufio.Reader) (string, bool, string, error) {
	method, err := br.Peek(len(http.MethodConnect))
	if err != nil {
		opErr, ok := err.(*net.OpError)
		if err != io.EOF && (!ok || !opErr.Timeout()) {
			log.WithoutContext().Errorf("Error while Peeking first %v bytes: %s", len(http.MethodConnect), err)
		}
		return "", false, "", err
	}

	if method := string(method); method != http.MethodConnect {
		return "", false, getPeeked(br), nil
	}

	req, err := http.ReadRequest(br)
	if err != nil {
		log.Errorf("Error while parsing CONNECT request: %s", err)
		return "", false, getPeeked(br), nil
	}

	return req.Host, true, "", nil
}

// clientHelloServerName returns the SNI server name inside the TLS ClientHello,
// without consuming any bytes from br.
// On any error, the empty string is returned.
func clientHelloServerName(br *bufio.Reader) (string, bool, string, error) {
	hdr, err := br.Peek(1)
	if err != nil {
		opErr, ok := err.(*net.OpError)
		if err != io.EOF && (!ok || !opErr.Timeout()) {
			log.WithoutContext().Errorf("Error while Peeking first byte: %s", err)
		}
		return "", false, "", err
	}

	const recordTypeHandshake = 0x16
	if hdr[0] != recordTypeHandshake {
		// log.Errorf("Error not tls")
		return "", false, getPeeked(br), nil // Not TLS.
	}

	const recordHeaderLen = 5
	hdr, err = br.Peek(recordHeaderLen)
	if err != nil {
		log.Errorf("Error while Peeking hello: %s", err)
		return "", false, getPeeked(br), nil
	}

	recLen := int(hdr[3])<<8 | int(hdr[4]) // ignoring version in hdr[1:3]
	helloBytes, err := br.Peek(recordHeaderLen + recLen)
	if err != nil {
		log.Errorf("Error while Hello: %s", err)
		return "", true, getPeeked(br), nil
	}

	sni := ""
	server := tls.Server(sniSniffConn{r: bytes.NewReader(helloBytes)}, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sni = hello.ServerName
			return nil, nil
		},
	})
	_ = server.Handshake()

	return sni, true, getPeeked(br), nil
}

func getPeeked(br *bufio.Reader) string {
	peeked, err := br.Peek(br.Buffered())
	if err != nil {
		log.Errorf("Could not get anything: %s", err)
		return ""
	}
	return string(peeked)
}

// sniSniffConn is a net.Conn that reads from r, fails on Writes,
// and crashes otherwise.
type sniSniffConn struct {
	r        io.Reader
	net.Conn // nil; crash on any unexpected use
}

// Read reads from the underlying reader
func (c sniSniffConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// Write crashes all the time
func (sniSniffConn) Write(p []byte) (int, error) { return 0, io.EOF }
