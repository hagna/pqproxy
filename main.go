package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	//	"code.google.com/p/leveldb-go/leveldb/db"
)

// openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days XXX

var ep = flag.String("ep", "", "endpoint of server")
var dburl = flag.String("dburl", "", "url of database")
var port = flag.String("port", ":5432", "port on which to pose as server")
var usessl = flag.Bool("ssl", false, "use ssl with postgres server but not between pqproxy and clients")
var cmd = flag.String("cmd", "", "stdin of cmd gets the bytes to read and stdout gives the bytes to write to postgres server")

type Mitm struct {
	/*
	   psql destination is the command line output of psql
	   psql source is postgres server

	   postgres source is psql client
	   postgres destination is the postgres server
	*/
	name string
	src  net.Conn
	dst  net.Conn
}

func Usage() {
	fmt.Printf("Usage: ./pqproxy -ssl -v 9 -dburl postgres://[user]:[pass]@[host][:port]/[database]\n\n")
	flag.PrintDefaults()
}

func shell(b *[]byte, name string) []byte {
	cmd := exec.Command(*cmd, name)
	Debug("shell", cmd)
	cmd.Stdin = bytes.NewReader(*b)
	res, err := cmd.CombinedOutput()
	if err != nil {
		Debug(string(res))
		log.Println(err)
	}
	return res
}

// Write to dst src -> dst
func (m Mitm) Write(b []byte) (n int, err error) {
	if m.name == "psql" {
		Debug("This was sent by the postgres server and we will write it to the client")
	} else {
		Debug("This was sent by the postgres client and we will write it to the postgres server")
	}

	// psql client send stuff to postgres server
	if m.name == "postgres" && *cmd != "" {
		res := shell(&b, "Write")
		if len(res) != 0 {
			n = len(b) // make the caller think we wrote it all
			_, err = m.dst.Write(res)
			Debug("We wrote this instead though")
			DebugDump(res)
			return
		}
	}
	DebugDump(b)
	n, err = m.dst.Write(b)

	Debug("Write finished")
	return
}

// Read from dst src <- dst
func (m Mitm) Read(b []byte) (n int, err error) {
	n, err = m.dst.Read(b)
	/*if m.name == "psql" && *cmd != "" {
		in := b[:n]
		res := shell(&in, "Read")
		if len(res) != 0 {
			Debug("replacing what we read from the client")
			b = []byte{}
			n = len(res)
			b = res
		}
	} */
	if m.name == "psql" {
		Debug("We read this from the client")
	} else {
		Debug("We read this from the server")
	}
	DebugDump(b[:n])
	Debug("Read finished")

	return
}

func postgreshandshake(client, server net.Conn) net.Conn {
	Debug("begin handshake")
	cb := make([]byte, 500)
	sb := make([]byte, 500)
	Debug("trying to read from client")
	n, err := client.Read(cb[:])
	if err != nil {
		Debug(err)
	}
	DebugDump("client said", cb[:n])
	Debug("Done reading from client", n)
	_, err = server.Write(cb[:n])
	if err != nil {
		Debug(err)
	}
	n, err = server.Read(sb[:])
	if err != nil {
		Debug(err)
	}
	DebugDump("server said", sb[:n])
	//newserver := server
	newserver := tls.Client(server, &tls.Config{InsecureSkipVerify: true})
	if *usessl {
		newserver = tls.Client(server, &tls.Config{InsecureSkipVerify: true})
		_, err = client.Write([]byte("N")) // we want the client to send plaintext to mitm
		if err != nil {
			Debug(err)
		}
	} else {
		n, err = client.Write(sb[:n])
		if err != nil {
			Debug(err)
		}

	}
	Debug("end handshake")
	return newserver

}

func main() {
	flag.Usage = Usage
	flag.Parse()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, os.Kill)
	clientCh := make(chan net.Conn)
	exit := make(chan struct{})

	if *dburl != "" {
		p, err := url.Parse(*dburl)
		if err == nil {
			*ep = p.Host
			p.Host = "127.0.0.1" + *port
			Info("NOTICE: use this url", p)
		} else {
			Fatal(err)
		}
	} else {
		Fatal("try --help")
	}

	go func() {

		ln, err := net.Listen("tcp", *port)
		if err != nil {
			Fatal(err)
		}
		for {
			conn, err := ln.Accept()
			if err != nil {
				Debug("error", err)
				continue
			}
			clientCh <- conn
		}
	}()

	go func() {
		defer func() {
			exit <- struct{}{}
		}()

	FOR:
		for {
			select {
			case s := <-c:
				log.Println("got signal", s)
				break FOR
			case conn := <-clientCh:
				go func(conn net.Conn) {
					remotename := conn.RemoteAddr()
					Info("connecting", remotename)
					defer conn.Close()
					sconn, err := net.Dial("tcp", *ep)
					if err != nil {
						Fatal(err)
					}
					defer sconn.Close()
					sconn = postgreshandshake(conn, sconn)
					defer sconn.Close()

					writeserver := Mitm{"postgres", conn, sconn}
					writeclient := Mitm{"psql", sconn, conn}
					Debug("got connection")
					go io.Copy(writeclient, writeserver)
					io.Copy(writeserver, writeclient)
					Info("end connection", remotename)

				}(conn)
			default:
				//non-blocking
			}

		}
	}()
	<-exit
}
