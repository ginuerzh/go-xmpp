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

	talk := xmpp.NewClient(*server, *username, *password,
		&xmpp.Options{NoTLS: *notls, Debug: *debug})

	talk.HandleFunc("iq:disco:info", func(client *xmpp.Client, stanza xmpp.Stanza) {
		info := stanza.(*xmpp.IQDiscoInfo)
		fmt.Println("got disco info:")
		if len(info.Identities) > 0 {
			fmt.Println("identities:")
			for _, id := range info.Identities {
				fmt.Printf("cat:%s, type:%s, name:%s\n", id.Category, id.Type, id.Name)
			}
		}
		if len(info.Features) > 0 {
			fmt.Println("features:")
			for _, f := range info.Features {
				fmt.Println(f)
			}
		}
	})

	talk.HandleFunc("iq:disco:items", func(client *xmpp.Client, stanza xmpp.Stanza) {
		if err := stanza.Error(); err != nil {
			fmt.Println(err)
		}
		items := stanza.(*xmpp.IQDiscoItems)
		fmt.Println("get disco items:")
		for _, i := range items.Items {
			fmt.Println(i.Jid + "(" + i.Name + ")")
		}
	})

	talk.HandleFunc("iq:roster", func(client *xmpp.Client, stanza xmpp.Stanza) {
		roster := stanza.(*xmpp.IQRoster)
		fmt.Println("got roster:")
		for _, item := range roster.Items() {
			fmt.Println(item.Jid)
		}
	})

	talk.HandleFunc("presence", func(client *xmpp.Client, stanza xmpp.Stanza) {
		p := stanza.(*xmpp.Presence)
		fmt.Println("got presence:", p.Jid, p.Status, p.Show)
	})

	talk.HandleFunc("message:state", func(client *xmpp.Client, stanza xmpp.Stanza) {
		state := stanza.(*xmpp.ChatState)
		fmt.Println("got chat state:", state.Jid, state.State)
	})

	talk.HandleFunc("message", func(client *xmpp.Client, stanza xmpp.Stanza) {
		msg := stanza.(*xmpp.Message)
		msg.To = msg.From
		msg.From = ""
		if len(msg.Body) > 0 {
			log.Println("got message", msg.To, msg.Body)
			client.Send(msg)
		}
	})
	log.Fatal(talk.Run())
}
