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

type Client struct {
	conn   io.ReadWriteCloser // connection to server
	jid    string             // Jabber ID for our connection
	domain string
	p      *xml.Decoder
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

// Options are used to specify additional options for new clients, such as a Resource.
type Options struct {
	// Host specifies what host to connect to, as either "hostname" or "hostname:port"
	// If host is not specified, the  DNS SRV should be used to find the host from the domainpart of the JID.
	// Default the port to 5222.
	Host string

	// User specifies what user to authenticate to the remote server.
	User string

	// Password supplies the password to use for authentication with the remote server.
	Password string

	// Resource specifies an XMPP client resource, like "bot", instead of accepting one
	// from the server.  Use "" to let the server generate one for your client.
	Resource string

	// NoTLS disables TLS and specifies that a plain old unencrypted TCP connection should
	// be used.
	NoTLS bool

	// Debug output
	Debug bool
}

// NewClient establishes a new Client connection based on a set of Options.
func (o Options) NewClient() (*Client, error) {
	host := o.Host
	c, err := connect(host, o.User, o.Password)
	if err != nil {
		return nil, err
	}

	client := new(Client)
	if !o.NoTLS {
		tlsconn := tls.Client(c, &DefaultConfig)
		if err = tlsconn.Handshake(); err != nil {
			return nil, err
		}
		if strings.LastIndex(o.Host, ":") > 0 {
			host = host[:strings.LastIndex(o.Host, ":")]
		}
		if err = tlsconn.VerifyHostname(host); err != nil {
			return nil, err
		}
		c = tlsconn
	}

	client.conn = c
	// For debugging: the following causes the plaintext of the connection to be duplicated to stdout.
	if o.Debug {
		client.conn = tee{c, os.Stdout}
	}

	if err := client.init(&o); err != nil {
		client.Close()
		return nil, err
	}

	return client, nil
}

// NewClient creates a new connection to a host given as "hostname" or "hostname:port".
// If host is not specified, the  DNS SRV should be used to find the host from the domainpart of the JID.
// Default the port to 5222.
func NewClient(host, user, passwd string, debug bool) (*Client, error) {
	opts := Options{
		Host:     host,
		User:     user,
		Password: passwd,
		Debug:    debug,
	}
	return opts.NewClient()
}

func NewClientNoTLS(host, user, passwd string, debug bool) (*Client, error) {
	opts := Options{
		Host:     host,
		User:     user,
		Password: passwd,
		NoTLS:    true,
		Debug:    debug,
	}
	return opts.NewClient()
}

func (c *Client) Close() error {
	return c.conn.Close()
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

func (c *Client) init(o *Options) error {
	c.p = xml.NewDecoder(c.conn)

	a := strings.SplitN(o.User, "@", 2)
	if len(a) != 2 {
		return errors.New("xmpp: invalid username (want user@domain): " + o.User)
	}
	user := a[0]
	domain := a[1]

	// Declare intent to be a jabber client.
	//fmt.Fprintf(c.conn, streamElem(domain))
	//c.SendOrg(streamElem(domain))
	c.Send(streamElem{domain: domain})
	// Server should respond with a stream opening.
	se, err := nextStart(c.p)
	if err != nil {
		return err
	}
	if se.Name.Space != nsStream || se.Name.Local != "stream" {
		return errors.New("xmpp: expected <stream> but got <" + se.Name.Local + "> in " + se.Name.Space)
	}

	// Now we're in the stream and can use Unmarshal.
	// Next message should be <features> to tell us authentication options.
	// See section 4.6 in RFC 3920.
	var f streamFeatures
	if err = c.p.DecodeElement(&f, nil); err != nil {
		return errors.New("unmarshal <features>: " + err.Error())
	}
	mechanism := ""
	for _, m := range f.Mechanisms.Mechanism {
		if m == mechanPlain {
			mechanism = m
			// Plain authentication: send base64-encoded \x00 user \x00 password.
			raw := "\x00" + user + "\x00" + o.Password
			enc := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
			base64.StdEncoding.Encode(enc, []byte(raw))
			c.Send(saslAuth{Mechanism: mechanPlain, Value: string(enc)})
			break
		}
		if m == mechanMd5 {
			continue
			mechanism = m
			// Digest-MD5 authentication
			///fmt.Fprintf(c.conn, "<auth xmlns='%s' mechanism='DIGEST-MD5'/>\n", nsSASL)
			c.Send(saslAuth{Mechanism: mechanMd5})
			var ch saslChallenge
			if err = c.p.DecodeElement(&ch, nil); err != nil {
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
			digest := saslDigestResponse(user, realm, o.Password, nonce, cnonceStr, "AUTHENTICATE", digestUri, nonceCount)
			message := "username=" + user + ", realm=" + realm + ", nonce=" + nonce + ", cnonce=" + cnonceStr + ", nc=" + nonceCount + ", qop=" + qop + ", digest-uri=" + digestUri + ", response=" + digest + ", charset=" + charset
			///fmt.Fprintf(c.conn, "<response xmlns='%s'>%s</response>\n", nsSASL, base64.StdEncoding.EncodeToString([]byte(message)))
			c.Send(saslResponse{Value: base64.StdEncoding.EncodeToString([]byte(message))})

			var rspauth saslSuccess
			if err = c.p.DecodeElement(&rspauth, nil); err != nil {
				return errors.New("unmarshal <success>: " + err.Error())
			}
			b, err = base64.StdEncoding.DecodeString(rspauth.Value)
			if err != nil {
				return err
			}
			//fmt.Println(string(b))
			///fmt.Fprintf(c.conn, "<response xmlns='%s'/>\n", nsSASL)
			c.Send(saslResponse{})
			break
		}
	}
	if mechanism == "" {
		return errors.New(fmt.Sprintf("PLAIN authentication is not an option: %v", f.Mechanisms.Mechanism))
	}

	// Next message should be either success or failure.
	name, val, err := next(c.p)
	if err != nil {
		return err
	}
	switch v := val.(type) {
	case *saslSuccess:
	case *saslFailure:
		// v.Any is type of sub-element in failure,
		// which gives a description of what failed.
		return errors.New("auth failure: " + v.Any.Local)
	default:
		return errors.New("expected <success> or <failure>, got <" + name.Local + "> in " + name.Space)
	}

	// Now that we're authenticated, we're supposed to start the stream over again.
	// Declare intent to be a jabber client.
	///fmt.Fprintf(c.conn, streamElem(domain))
	c.Send(&streamElem{domain: domain})

	// Here comes another <stream> and <features>.
	se, err = nextStart(c.p)
	if err != nil {
		return err
	}
	if se.Name.Space != nsStream || se.Name.Local != "stream" {
		return errors.New("expected <stream>, got <" + se.Name.Local + "> in " + se.Name.Space)
	}
	if err = c.p.DecodeElement(&f, nil); err != nil {
		// TODO: often stream stop.
		//return os.NewError("unmarshal <features>: " + err.String())
	}

	//fmt.Println("method:", f.Compress.Method, f.Session.XMLName.Local, f.Bind.XMLName.Local)
	// Send IQ message asking to bind to the local user name.
	iq := NewIQ(IQSet, "")
	if o.Resource == "" {
		///fmt.Fprintf(c.conn, "<iq type='set' id='x'><bind xmlns='%s'></bind></iq>\n", nsBind)
		iq.SetElem(bindBind{})
	} else {
		//fmt.Fprintf(c.conn, "<iq type='set' id='x'><bind xmlns='%s'><resource>%s</resource></bind></iq>\n", nsBind, o.Resource)
		iq.SetElem(bindBind{Resource: o.Resource})
	}
	c.Send(iq)

	//var iq clientIQ
	iq.SetElem(bindBind{})
	if err = c.p.DecodeElement(&iq, nil); err != nil {
		return errors.New("unmarshal <iq>: " + err.Error())
	}
	fmt.Println("afsdfsdf", iq)
	/*
		if &iq.Bind == nil {
			return errors.New("<iq> result missing <bind>")
		}
		c.jid = iq.Bind.Jid // our local id
	*/
	// We're connected and can now receive and send messages.
	fmt.Fprintf(c.conn, "<presence xml:lang='en'><show>xa</show><status>I for one welcome our new codebot overlords.</status></presence>")
	return nil
}

type Chat struct {
	Remote string
	Type   string
	Text   string
	Other  []string
}

type Presence struct {
	From string
	To   string
	Type string
	Show string
}

// Recv wait next token of chat.
func (c *Client) Recv() (event interface{}, err error) {
	for {
		_, val, err := next(c.p)
		if err != nil {
			return Chat{}, err
		}
		switch v := val.(type) {
		case *clientMessage:
			return Chat{v.From, v.Type, v.Body, v.Other}, nil
		case *clientPresence:
			return Presence{v.From, v.To, v.Type, v.Show}, nil
		}
	}
	panic("unreachable")
}

/*
// Send sends message text.
func (c *Client) Send(chat Chat) {
	fmt.Fprintf(c.conn, "<message to='%s' type='%s' xml:lang='en'>"+
		"<body>%s</body></message>",
		xmlEscape(chat.Remote), xmlEscape(chat.Type), xmlEscape(chat.Text))
}
*/
func (c *Client) Send(elem Elementer) {
	fmt.Fprint(c.conn, elem.String())
}

// Send origin
func (c *Client) SendOrg(org string) {
	fmt.Fprint(c.conn, org)
}

// Scan XML token stream to find next StartElement.
func nextStart(p *xml.Decoder) (xml.StartElement, error) {
	for {
		t, err := p.Token()
		if err != nil && err != io.EOF {
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

// Scan XML token stream for next element and save into val.
// If val == nil, allocate new element based on proto map.
// Either way, return val.
func next(p *xml.Decoder) (xml.Name, interface{}, error) {
	// Read start element to find out what type we want.
	se, err := nextStart(p)
	if err != nil {
		return xml.Name{}, nil, err
	}

	// Put it in an interface and allocate one.
	var nv interface{}
	switch se.Name.Space + " " + se.Name.Local {
	case nsStream + " features":
		nv = &streamFeatures{}
	case nsStream + " error":
		nv = &streamError{}
	case nsTLS + " starttls":
		nv = &tlsStartTLS{}
	case nsTLS + " proceed":
		nv = &tlsProceed{}
	case nsTLS + " failure":
		nv = &tlsFailure{}
	case nsSASL + " mechanisms":
		nv = &saslMechanisms{}
	case nsSASL + " challenge":
		nv = ""
	case nsSASL + " response":
		nv = ""
	case nsSASL + " abort":
		nv = &saslAbort{}
	case nsSASL + " success":
		nv = &saslSuccess{}
	case nsSASL + " failure":
		nv = &saslFailure{}
	case nsBind + " bind":
		nv = &bindBind{}
	case nsClient + " message":
		nv = &clientMessage{}
	case nsClient + " presence":
		nv = &clientPresence{}
	case nsClient + " iq":
		nv = &clientIQ{}
	case nsClient + " error":
		nv = &clientError{}
	default:
		return xml.Name{}, nil, errors.New("unexpected XMPP message " +
			se.Name.Space + " <" + se.Name.Local + "/>")
	}

	// Unmarshal into that storage.
	if err = p.DecodeElement(nv, &se); err != nil {
		return xml.Name{}, nil, err
	}
	return se.Name, nv, err
}

type tee struct {
	c net.Conn
	w io.Writer
}

func (t tee) Read(p []byte) (n int, err error) {
	n, err = t.c.Read(p)
	if n > 0 {
		t.w.Write([]byte(">>> "))
		t.w.Write(p[0:n])
		t.w.Write([]byte("\n"))
	}
	return
}

func (t tee) Write(p []byte) (n int, err error) {
	n, err = t.c.Write(p)
	if n > 0 {
		t.w.Write([]byte("<<< "))
		t.w.Write(p[:n])
		t.w.Write([]byte("\n"))
	}
	return
}

func (t tee) Close() error {
	return t.c.Close()
}
