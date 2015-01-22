package main

import (
	_ "bufio"
	"code.google.com/p/leveldb-go/leveldb"
	"crypto/tls"
	"flag"
	"github.com/davecgh/go-spew/spew"
	"io"
	"log"
	"net"
	//	"code.google.com/p/leveldb-go/leveldb/db"
)

var DB *leveldb.DB

type Mitm struct {
	name string
	src net.Conn
	dst net.Conn
}

// Write to dst
func (m Mitm) Write(b []byte) (n int, err error) {
	n, err = m.dst.Write(b)
	Debug(m.name, "src -> dst")
	spew.Dump(b[:n])
	Debug("Write finished")
	return
	/*m.write <- b
	return m.w.Write(<-m.write)*/
}

// Read from dst
func (m Mitm) Read(b []byte) (n int, err error) {
	n, err = m.dst.Read(b)
	Debug(m.name, "src <- dst")
	spew.Dump(b[:n])
	Debug("Read finished")
	return
	/*n, err = m.r.Read(b)
	m.read <- b[:n]
	b = <-m.read
	n = len(b)
	return n, err*/
}

/*
func (m Mitm) events() {
	for {
		var k, v []byte
		select {
		case tosrv := <-m.write:
			Debug("Client -> Server")
			spew.Dump(tosrv)
			k = tosrv
			if dat, err := DB.Get(k, nil); err == nil {
				Debug("found i in cache")
				spew.Dump(k)
				spew.Dump(dat)
			} else {
				Debug("cache miss")
				m.write <- tosrv
			}

		case fromsrv := <-m.read:

			v = fromsrv
			m.read <- fromsrv
			Debug(DB)
			err := DB.Set(k, v, nil)
			if err != nil {
				Debug(err)
			}
			Debug("Read finished")
		}
	}
}
*/

// openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days XXX

var ep = flag.String("ep", ":5433", "endpoint of server")
var port = flag.String("port", ":5432", "port on which to pose as server")
var postgres = flag.Bool("postgres", false, "do the postgres handshake for SSL server and plain text client")
var dbname = flag.String("dbname", "", "name of leveldb for storage")

func postgreshandshake(client, server net.Conn) net.Conn {
	cb := [1024]byte{}
	sb := [1024]byte{}
	Debug("trying to read from client")
	n, err := client.Read(cb[:])
	if err != nil {
		Debug(err)
	}
	Debug("Done reading from client", n)
	_, err = server.Write(cb[:n])
	if err != nil {
		Debug(err)
	}
	n, err = server.Read(sb[:])
	if err != nil {
		Debug(err)
	}
	newserver := tls.Client(server, &tls.Config{InsecureSkipVerify: true})
	_, err = client.Write([]byte("N")) // we want the client to send plaintext to mitm
	if err != nil {
		Debug(err)
	}
	return newserver

}

func main() {
	flag.Parse()

	ln, err := net.Listen("tcp", *port)
	if err != nil {
		log.Fatal(err)
	}
	DB, err = leveldb.Open(*dbname, nil)
	if err != nil {
		Error(err, DB)
	}
	Debug(DB)
	defer DB.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				Debug("error", err)
				continue
			}
			sconn, err := net.Dial("tcp", *ep)
			if err != nil {
				log.Fatal(err)
			}
			if *postgres {
				sconn = postgreshandshake(conn, sconn)
			}
			writeserver := Mitm{"postgres", conn, sconn}
			writeclient := Mitm{"psql", sconn, conn}
			Debug("got connection")
			go io.Copy(writeclient, writeserver)
			go io.Copy(writeserver, writeclient)
			Debug("END")

		}
	}()
	select {}
}
