package main

import (
	_ "bufio"
	"code.google.com/p/leveldb-go/leveldb"
	"crypto/tls"
	"flag"
	"github.com/davecgh/go-spew/spew"
	"io"
	"log"
	"os/exec"
	"bytes"
	"net"
	//	"code.google.com/p/leveldb-go/leveldb/db"
)

var DB *leveldb.DB

// openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days XXX

var ep = flag.String("ep", ":5433", "endpoint of server")
var port = flag.String("port", ":5432", "port on which to pose as server")
var postgres = flag.Bool("postgres", false, "do the postgres handshake for SSL server and plain text client")
var dbname = flag.String("dbname", "", "name of leveldb for storage")
var cmd = flag.String("cmd", "", "stdin of cmd gets the bytes to read and stdout gives the bytes to write to postgres server")

type Mitm struct {
/* 
psql destination is the command line output of psql
psql source is postgres server 

postgres source is psql client 
postgres destination is the postgres server
*/
	name string
	src net.Conn
	dst net.Conn
}


func shell(b *[]byte) []byte {
	cmd := exec.Command(*cmd)
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
	spew.Dump(b)
	// psql client send stuff to postgres server
	if m.name == "psql" && *cmd != "" {
		res := shell(&b)
		if len(res) != 0 {
			n, err = m.dst.Write(res)
			b = res
			return
		}
	}  
	n, err = m.dst.Write(b)


	Debug("Write finished")
	return
}

// Read from dst src <- dst
func (m Mitm) Read(b []byte) (n int, err error) {
	n, err = m.dst.Read(b)
	if m.name == "psql" && *cmd != "" {
		in := b[:n]
		res := shell(&in)
		if len(res) != 0 {
			l, e := m.dst.Write(res)
			Debug("Wrote", l, e)
			spew.Dump(res[:l])
			n = 0
			b = []byte{}
		}
	} 
	if m.name == "psql" {
		Debug("We read this from the client")
	} else {
		Debug("We read this from the server")
	}
	spew.Dump(b[:n])
	Debug("Read finished")

	return
}

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
