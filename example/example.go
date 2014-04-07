package main

import (
	//"bufio"
	"flag"
	"fmt"
	"github.com/ginuerzh/go-xmpp"
	"log"
	"os"
	//"strings"
)

var server = flag.String("server", "talk.google.com:443", "server")
var username = flag.String("username", "", "username")
var password = flag.String("password", "", "password")
var notls = flag.Bool("notls", false, "No TLS")
var debug = flag.Bool("debug", false, "debug output")

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: example [options]\n")
		flag.PrintDefaults()
		os.Exit(2)
	}
	flag.Parse()
	if *username == "" || *password == "" {
		flag.Usage()
	}

	talk := xmpp.Client{
		Host:     *server,
		User:     *username,
		Password: *password,
		Opts: &xmpp.Options{
			NoTLS: *notls,
			Debug: *debug,
		},
	}

	talk.Start()
	talk.RosterHandleFunc(func(roster *xmpp.Roster) {
		log.Println("got roster")
		for _, item := range roster.Items() {
			fmt.Println(item.Jid)
		}
	})
	talk.PresenceHandleFunc(func(p *xmpp.Presence) {
		log.Println("got presence from", p.Jid)
	})
	talk.Send(&xmpp.Presence{})
	talk.SyncRoster()

	for {
		_, err := talk.Recv()
		if err != nil {
			log.Fatal(err)
		}
		//log.Println("recv:", stanza)
	}
	/*
		log.Fatal(talk.StartAndRecv(func(c *xmpp.Client, st xmpp.Stanzar) {
			log.Println(st, st.Err())
		}))
	*/
}
