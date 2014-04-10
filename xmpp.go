// Copyright 2011 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// TODO(rsc):
//	More precise error handling.
//	Presence functionality.
// TODO(mattn):
//  Add proxy authentication.

// Package xmpp implements a simple Google Talk client
// using the XMPP protocol described in RFC 3920 and RFC 3921.
package xmpp

import (
	"bufio"
	//"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

var DefaultConfig tls.Config = tls.Config{InsecureSkipVerify: true}

type HandlerFunc func(client *Client, sta Stanza)

type Options struct {
	// Resource specifies an XMPP client resource, like "bot", instead of accepting one
	// from the server.  Use "" to let the server generate one for your client.
	Resource string

	// NoTLS disables TLS and specifies that a plain old unencrypted TCP connection should
	// be used.
	NoTLS bool

	TlsConfig *tls.Config

	// Debug output
	Debug bool
}

type Client struct {
	// Host specifies what host to connect to, as either "hostname" or "hostname:port"
	// If host is not specified, the  DNS SRV should be used to find the host from the domainpart of the JID.
	// Default the port to 5222.
	Host string

	// User specifies what user to authenticate to the remote server.
	User string

	// Password supplies the password to use for authentication with the remote server.
	Password string

	// Jabber ID for our connection
	Jid string

	// connection to server
	conn *Conn

	// handlers for received stanzas
	handlers map[string]HandlerFunc

	dec *xml.Decoder
	enc *xml.Encoder

	Opts *Options
}

func NewClient(host, user, pwd string, opts *Options) *Client {
	return &Client{
		Host:     host,
		User:     user,
		Password: pwd,
		handlers: make(map[string]HandlerFunc),
		Opts:     opts,
	}
}

func (c *Client) HandleFunc(pattern string, handler HandlerFunc) {
	c.handlers[pattern] = handler
}

func (c *Client) Run() error {
	if err := c.start(); err != nil {
		return err
	}

	for {
		e, err := c.recvStanza()
		if err != nil {
			fmt.Println(err)
			return err
		}

		for _, st := range c.decode(e) {
			if handler, ok := c.handlers[st.Type()]; ok {
				handler(c, st)
			}
		}
	}

	panic("unreachable")
}

func (c *Client) start() error {
	if c.Opts == nil {
		c.Opts = &Options{
			TlsConfig: &DefaultConfig,
		}
	}

	host := c.Host
	conn, err := connect(host, c.User, c.Password)
	if err != nil {
		return err
	}

	if c.Opts.Debug {
		c.conn = NewConn(conn, os.Stdout)
	} else {
		c.conn = NewConn(conn, nil)
	}

	if !c.Opts.NoTLS {
		if err := c.conn.handshake(c.Host, c.Opts.TlsConfig); err != nil {
			return err
		}
	}

	if err := c.init(); err != nil {
		c.Close()
		return err
	}

	return nil
}

func (c *Client) decode(e elementer) []Stanza {
	var stans []Stanza
	var st Stanza

	switch e.Name() {
	case "iq":
		iq := e.(*stanIQ)

		if iq.Ping != nil {
			iq.T = "result"
			iq.To = iq.From
			iq.From = ""
			iq.Ping = nil
			c.send(iq)
			return nil
		}

		if iq.Roster != nil && iq.T != "set" {
			st = &IQRoster{}
		}

		if iq.DiscoInfo != nil {
			st = &IQDiscoInfo{}
		}

		if iq.DiscoItems != nil {
			st = &IQDiscoItems{}
		}
	case "presence":
		st = &Presence{}
	case "message":
		state := &ChatState{}
		state.decode(e)
		if state.State != "" {
			stans = append(stans, state)
		}

		if len(e.(*stanMessage).Body) > 0 {
			st = &Message{}
		}
	}

	st.decode(e)
	stans = append(stans, st)

	return stans
}

func (c *Client) recvStanza() (elementer, error) {
	se, err := nextStart(c.dec)
	if err != nil {
		return nil, err
	}
	var e elementer
	switch se.Name.Space + " " + se.Name.Local {
	case nsClient + " iq":
		e = &stanIQ{}
	case nsClient + " presence":
		e = &stanPresence{}
	case nsClient + " message":
		e = &stanMessage{}
	default:
		return nil, errors.New("unexpected XMPP message " +
			se.Name.Space + " <" + se.Name.Local + "/>")
	}

	// Unmarshal into that storage.
	if err = c.dec.DecodeElement(e, &se); err != nil {
		return nil, err
	}

	return e, nil
}

func (c *Client) recvElem(e elementer) (err error) {
	se, err := nextStart(c.dec)
	if err != nil {
		return err
	}

	switch se.Name.Space + " " + se.Name.Local {
	// stream start element
	case nsStream + " stream":
		if _, ok := e.(*xmppStream); !ok {
			return errors.New("xmpp: expected <stream> but got <" +
				se.Name.Local + "> in " + se.Name.Space)
		}
		return nil
	// sasl failure
	case nsStream + " error":
		serr := &streamError{}
		err = serr
		e = serr
	case nsSASL + " failure":
		fail := &saslFailure{}
		err = fail
		e = fail
		// sasl abort
	case nsSASL + " abort":
		abort := &saslAbort{}
		err = abort
		e = abort
		// tls failture
	case nsTLS + " failure":
		fail := &tlsFailure{}
		err = fail
		e = fail
	}

	if err := c.dec.DecodeElement(e, &se); err != nil {
		return err
	}

	return
}

func (c *Client) send(e elementer) error {
	return c.enc.Encode(e)
}

func (c *Client) sendRaw(data []byte) error {
	_, err := c.conn.Write(data)
	return err
}

func (c *Client) Send(st Stanza) error {
	return c.send(st.encode())
}

func (c *Client) Close() error {
	c.sendRaw([]byte("</stream:stream>"))
	return c.conn.Close()
}

func (c *Client) request(req elementer, resp elementer) error {
	if err := c.send(req); err != nil {
		return err
	}
	return c.recvElem(resp)
}

func (c *Client) openStream(domain string) (*streamFeatures, error) {
	if err := c.sendRaw(streamElement(domain)); err != nil {
		return nil, err
	}
	if err := c.recvElem(&xmppStream{}); err != nil {
		return nil, err
	}

	f := &streamFeatures{}
	if err := c.recvElem(f); err != nil {
		return nil, errors.New("unmarshal <features>: " + err.Error())
	}
	return f, nil
}

func (c *Client) auth(mechanism string, domain, username, password string) error {
	switch mechanism {
	case "PLAIN":
		// Plain authentication: send base64-encoded \x00 user \x00 password.
		raw := "\x00" + username + "\x00" + password
		enc := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
		base64.StdEncoding.Encode(enc, []byte(raw))
		if err := c.request(
			&saslAuth{Mechanism: mechanPlain, Value: string(enc)},
			&saslSuccess{}); err != nil {
			return err
		}
	case "DIGEST-MD5":
		// Digest-MD5 authentication
		var ch saslChallenge
		if err := c.request(saslAuth{Mechanism: mechanMd5}, &ch); err != nil {
			return errors.New("unmarshal <challenge>: " + err.Error())
		}

		b, err := base64.StdEncoding.DecodeString(ch.Value)
		if err != nil {
			return err
		}
		tokens := map[string]string{}
		for _, token := range strings.Split(string(b), ",") {
			kv := strings.SplitN(strings.TrimSpace(token), "=", 2)
			if len(kv) == 2 {
				if kv[1][0] == '"' && kv[1][len(kv[1])-1] == '"' {
					kv[1] = kv[1][1 : len(kv[1])-1]
				}
				tokens[kv[0]] = kv[1]
			}
		}
		realm, _ := tokens["realm"]
		nonce, _ := tokens["nonce"]
		qop, _ := tokens["qop"]
		charset, _ := tokens["charset"]
		cnonceStr := cnonce()
		digestUri := "xmpp/" + domain
		nonceCount := fmt.Sprintf("%08x", 1)
		digest := saslDigestResponse(username, realm, password, nonce, cnonceStr, "AUTHENTICATE", digestUri, nonceCount)
		message := "username=" + username + ", realm=" + realm + ", nonce=" + nonce + ", cnonce=" + cnonceStr + ", nc=" + nonceCount + ", qop=" + qop + ", digest-uri=" + digestUri + ", response=" + digest + ", charset=" + charset
		///fmt.Fprintf(c.conn, "<response xmlns='%s'>%s</response>\n", nsSASL, base64.StdEncoding.EncodeToString([]byte(message)))
		var rspauth saslSuccess
		if err := c.request(&saslResponse{Value: base64.StdEncoding.EncodeToString([]byte(message))}, &rspauth); err != nil {
			return errors.New("unmarshal <success>: " + err.Error())
		}
		b, err = base64.StdEncoding.DecodeString(rspauth.Value)
		if err != nil {
			return err
		}
	default:
		return errors.New("unsupported mechanism: " + mechanism)
	}

	return nil
}

func (c *Client) init() error {
	c.dec = xml.NewDecoder(c.conn)
	c.enc = xml.NewEncoder(c.conn)

	a := strings.SplitN(c.User, "@", 2)
	if len(a) != 2 {
		return errors.New("xmpp: invalid username (want user@domain): " + c.User)
	}
	user := a[0]
	domain := a[1]

	features, err := c.openStream(domain)
	if err != nil {
		return err
	}

	if features.StartTLS != nil && features.StartTLS.Required() {
		if err := c.request(&tlsStartTLS{}, &tlsProceed{}); err != nil {
			return err
		}
		if err := c.conn.handshake(domain, c.Opts.TlsConfig); err != nil {
			return err
		}

		features, err = c.openStream(domain)
		if err != nil {
			return err
		}
	}

	var authErr error
	for _, m := range features.Mechanisms.Mechanism {
		if authErr = c.auth(m, domain, user, c.Password); authErr == nil {
			break
		}
	}
	if authErr != nil {
		return errors.New(
			fmt.Sprintf("PLAIN authentication is not an option: %v",
				features.Mechanisms.Mechanism))
	}

	// Now that we're authenticated, we're supposed to start the stream over again.
	// Declare intent to be a jabber client.
	// Here comes another <stream> and <features>.
	features, err = c.openStream(domain)
	if err != nil {
		return err
	}

	// Send IQ message asking to bind to the local user name.
	reqIQ, resIQ := &stanIQ{}, &stanIQ{}
	reqIQ.T = IQSet
	reqIQ.Bind = &bindBind{Resource: c.Opts.Resource}
	if err := c.request(reqIQ, resIQ); err != nil {
		return errors.New("bind: " + err.Error())
	}

	c.Jid = resIQ.Bind.Jid // our local id
	fmt.Println("Jid:", c.Jid)

	// open session
	reqIQ, resIQ = &stanIQ{}, &stanIQ{}
	reqIQ.T = IQSet
	reqIQ.Session = &session{}
	if err := c.request(reqIQ, resIQ); err != nil {
		return errors.New("session: " + err.Error())
	}

	c.Send(&Presence{})
	c.Send(&IQRoster{})
	c.Send(&IQDiscoItems{})
	c.Send(&IQDiscoInfo{})

	return nil
}

func connect(host, user, passwd string) (net.Conn, error) {
	addr := host

	if strings.TrimSpace(host) == "" {
		a := strings.SplitN(user, "@", 2)
		if len(a) == 2 {
			host = a[1]
		}
	}
	a := strings.SplitN(host, ":", 2)
	if len(a) == 1 {
		host += ":5222"
	}
	proxy := os.Getenv("HTTP_PROXY")
	if proxy == "" {
		proxy = os.Getenv("http_proxy")
	}
	if proxy != "" {
		url, err := url.Parse(proxy)
		if err == nil {
			addr = url.Host
		}
	}
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	if proxy != "" {
		fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\n", host)
		fmt.Fprintf(c, "Host: %s\r\n", host)
		fmt.Fprintf(c, "\r\n")
		br := bufio.NewReader(c)
		req, _ := http.NewRequest("CONNECT", host, nil)
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 {
			f := strings.SplitN(resp.Status, " ", 2)
			return nil, errors.New(f[1])
		}
	}
	return c, nil
}

func saslDigestResponse(username, realm, passwd, nonce, cnonceStr,
	authenticate, digestUri, nonceCountStr string) string {
	h := func(text string) []byte {
		h := md5.New()
		h.Write([]byte(text))
		return h.Sum(nil)
	}
	hex := func(bytes []byte) string {
		return fmt.Sprintf("%x", bytes)
	}
	kd := func(secret, data string) []byte {
		return h(secret + ":" + data)
	}

	a1 := string(h(username+":"+realm+":"+passwd)) + ":" +
		nonce + ":" + cnonceStr
	a2 := authenticate + ":" + digestUri
	response := hex(kd(hex(h(a1)), nonce+":"+
		nonceCountStr+":"+cnonceStr+":auth:"+
		hex(h(a2))))
	return response
}

func cnonce() string {
	randSize := big.NewInt(0)
	randSize.Lsh(big.NewInt(1), 64)
	cn, err := rand.Int(rand.Reader, randSize)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%016x", cn)
}

// Scan XML token stream to find next StartElement.
func nextStart(p *xml.Decoder) (xml.StartElement, error) {
	for {
		t, err := p.Token()
		if err != nil && err != io.EOF {
			fmt.Println(err)
			return xml.StartElement{}, err
		}
		switch t := t.(type) {
		case xml.StartElement:
			return t, nil
		case xml.EndElement:
			return xml.StartElement{}, errors.New("End element: " + t.Name.Local)
		}
	}
	panic("unreachable")
}

type Conn struct {
	c net.Conn
	w io.Writer
}

func NewConn(conn net.Conn, logger io.Writer) *Conn {
	return &Conn{
		c: conn,
		w: logger,
	}
}

func (t *Conn) Read(p []byte) (n int, err error) {
	n, err = t.c.Read(p)
	if n > 0 && t.w != nil {
		t.w.Write([]byte(">>> "))
		t.w.Write(p[0:n])
		t.w.Write([]byte("\n"))
	}
	return
}

func (t *Conn) Write(p []byte) (n int, err error) {
	n, err = t.c.Write(p)
	if n > 0 && t.w != nil {
		t.w.Write([]byte("<<< "))
		t.w.Write(p[:n])
		t.w.Write([]byte("\n"))
	}
	return
}

func (t *Conn) handshake(host string, config *tls.Config) error {
	if config == nil {
		config = &DefaultConfig
	}
	tlsconn := tls.Client(t.c, config)
	if err := tlsconn.Handshake(); err != nil {
		return err
	}

	if strings.LastIndex(host, ":") > 0 {
		host = host[:strings.LastIndex(host, ":")]
	}
	if err := tlsconn.VerifyHostname(host); err != nil {
		return err
	}
	t.c = tlsconn
	return nil
}

func (t *Conn) Close() error {
	return t.c.Close()
}
