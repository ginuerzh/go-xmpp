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

type HandlerFunc func(client *Client, sta Stanzar)

type RosterHandler func(roster *Roster)

type PresenceHandler func(presence *Presence)

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

	// handler for received stanzas
	handler         HandlerFunc
	rosterHandler   RosterHandler
	presenceHandler PresenceHandler

	p *xml.Decoder

	Opts *Options
}

func (c *Client) RosterHandleFunc(handler RosterHandler) {
	c.rosterHandler = handler
}

func (c *Client) PresenceHandleFunc(handler PresenceHandler) {
	c.presenceHandler = handler
}

func (c *Client) Start() error {
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

func (c *Client) StartAndRecv(handler HandlerFunc) error {
	if err := c.Start(); err != nil {
		return err
	}

	for {
		st, err := c.Recv()
		if err != nil {
			fmt.Println(err)
			return err
		}
		if handler != nil {
			handler(c, st)
		}
	}
}

func (c *Client) Recv() (Stanzar, error) {
	se, err := nextStart(c.p)
	if err != nil {
		return nil, err
	}
	var st elementer
	switch se.Name.Space + " " + se.Name.Local {
	case nsClient + " iq":
		st = &stanIQ{}
	case nsClient + " presence":
		st = &stanPresence{}
	default:
		return nil, errors.New("unexpected XMPP message " +
			se.Name.Space + " <" + se.Name.Local + "/>")
	}

	// Unmarshal into that storage.
	if err = c.p.DecodeElement(st, &se); err != nil {
		return nil, err
	}

	switch st.Name() {
	case "iq":
		iq := st.(*stanIQ)
		if iq.Roster != nil && c.rosterHandler != nil {
			c.rosterHandler(decodeRoster(iq.Roster))
		}
	case "presence":
		if c.presenceHandler != nil {
			p := &Presence{}
			p.decode(st.(*stanPresence))
			c.presenceHandler(p)
		}
	}
	return nil, nil
}

func (c *Client) recvElem(e elementer) (err error) {
	se, err := nextStart(c.p)
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

	if err := c.p.DecodeElement(e, &se); err != nil {
		return err
	}

	return
}

func (c *Client) send(e elementer) error {
	b, err := xml.Marshal(e)
	if err != nil {
		return err
	}

	return c.sendRaw(b)
}

func (c *Client) sendRaw(data []byte) error {
	_, err := c.conn.Write(data)
	return err
}

func (c *Client) Send(st Stanzar) error {
	return c.sendRaw(st.Encode())
}

func (c *Client) request(req elementer, resp elementer) error {
	if err := c.send(req); err != nil {
		return err
	}
	return c.recvElem(resp)
}

func (c *Client) init() error {
	c.p = xml.NewDecoder(c.conn)

	a := strings.SplitN(c.User, "@", 2)
	if len(a) != 2 {
		return errors.New("xmpp: invalid username (want user@domain): " + c.User)
	}
	user := a[0]
	domain := a[1]

	if err := c.sendRaw(streamElement(domain)); err != nil {
		return err
	}
	// Declare intent to be a jabber client.
	// Server should respond with a stream opening.
	if err := c.recvElem(&xmppStream{}); err != nil {
		return err
	}

	// Now we're in the stream and can use Unmarshal.
	// Next message should be <features> to tell us authentication options.
	// See section 4.6 in RFC 3920.
	var f streamFeatures
	if err := c.recvElem(&f); err != nil {
		return errors.New("unmarshal <features>: " + err.Error())
	}
	//fmt.Println("features:", f)

	if f.StartTLS != nil && f.StartTLS.Required() {
		if err := c.request(&tlsStartTLS{}, &tlsProceed{}); err != nil {
			return err
		}
		if err := c.conn.handshake(domain, c.Opts.TlsConfig); err != nil {
			return err
		}

		if err := c.sendRaw(streamElement(domain)); err != nil {
			return err
		}
		if err := c.recvElem(&xmppStream{}); err != nil {
			return err
		}

		f = streamFeatures{}
		if err := c.recvElem(&f); err != nil {
			return errors.New("unmarshal <features>: " + err.Error())
		}
		//fmt.Println("features:", f)
	}

	mechanism := ""
	for _, m := range f.Mechanisms.Mechanism {
		if m == mechanPlain {
			mechanism = m
			// Plain authentication: send base64-encoded \x00 user \x00 password.
			raw := "\x00" + user + "\x00" + c.Password
			enc := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
			base64.StdEncoding.Encode(enc, []byte(raw))
			c.send(&saslAuth{Mechanism: mechanPlain, Value: string(enc)})
			break
		}
		if m == mechanMd5 {
			continue
			mechanism = m
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
			digest := saslDigestResponse(user, realm, c.Password, nonce, cnonceStr, "AUTHENTICATE", digestUri, nonceCount)
			message := "username=" + user + ", realm=" + realm + ", nonce=" + nonce + ", cnonce=" + cnonceStr + ", nc=" + nonceCount + ", qop=" + qop + ", digest-uri=" + digestUri + ", response=" + digest + ", charset=" + charset
			///fmt.Fprintf(c.conn, "<response xmlns='%s'>%s</response>\n", nsSASL, base64.StdEncoding.EncodeToString([]byte(message)))
			c.send(&saslResponse{Value: base64.StdEncoding.EncodeToString([]byte(message))})

			var rspauth saslSuccess
			if err := c.request(&saslResponse{Value: base64.StdEncoding.EncodeToString([]byte(message))}, &rspauth); err != nil {
				return errors.New("unmarshal <success>: " + err.Error())
			}
			b, err = base64.StdEncoding.DecodeString(rspauth.Value)
			if err != nil {
				return err
			}
			//fmt.Println(string(b))
			///fmt.Fprintf(c.conn, "<response xmlns='%s'/>\n", nsSASL)
			c.send(&saslResponse{})
			break
		}
	}
	if mechanism == "" {
		return errors.New(fmt.Sprintf("PLAIN authentication is not an option: %v", f.Mechanisms.Mechanism))
	}

	// Next message should be either success or failure.
	var v saslSuccess
	err := c.recvElem(&v)
	if err != nil {
		return err
	}

	// Now that we're authenticated, we're supposed to start the stream over again.
	// Declare intent to be a jabber client.
	// Here comes another <stream> and <features>.
	if err := c.sendRaw(streamElement(domain)); err != nil {
		return err
	}
	if err := c.recvElem(&xmppStream{}); err != nil {
		return err
	}

	f = streamFeatures{}
	if err := c.recvElem(&f); err != nil {
		return errors.New("unmarshal <features>: " + err.Error())
	}

	// Send IQ message asking to bind to the local user name.
	iq := &stanIQ{}
	iq.T = IQSet
	iq.Bind = &bindBind{}
	if c.Opts.Resource != "" {
		//fmt.Fprintf(c.conn, "<iq type='set' id='x'><bind xmlns='%s'><resource>%s</resource></bind></iq>\n", nsBind, o.Resource)
		iq.Bind = &bindBind{Resource: c.Opts.Resource}
	}
	resIQ := stanIQ{}
	if err := c.request(iq, &resIQ); err != nil {
		return errors.New("unmarshal <iq>: " + err.Error())
	}

	if resIQ.Bind == nil {
		return errors.New("<iq> result missing <bind>")
	}
	c.Jid = resIQ.Bind.Jid // our local id
	fmt.Println("Jid:", c.Jid)
	// We're connected and can now receive and send messages.
	//p := StanPresence{}
	//return c.Send(p)

	return nil
}

func (c *Client) SyncRoster() error {
	iq := &stanIQ{}
	iq.T = IQGet
	iq.Roster = &rosterQuery{}
	return c.send(iq)
}

func (c *Client) Close() error {
	return c.conn.Close()
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
			return xml.StartElement{}, errors.New("End Element")
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
