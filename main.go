package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"

	"database/sql"
	"github.com/hagna/pqproxy/pq"
)

var dburl = flag.String("dburl", "", "url of database")
var port = flag.String("port", ":5432", "port on which to pose as server")
var cmd = flag.String("cmd", "", "stdin of cmd gets the bytes to read and stdout gives the bytes to write to postgres server")
var testquery = flag.String("t", "", "test query to try")

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
	fmt.Printf("Usage: ./pqproxy [options] postgres://[user]:[pass]@[host][:port]/[database]\n\n")
	flag.PrintDefaults()
}

/*
// Write to dst src -> dst
	if m.name == "psql" {
		pq.Debug("This was sent by the postgres server and we will write it to the client")
	} else {
		pq.Debug("This was sent by the postgres client and we will write it to the postgres server")
	}

	// psql client send stuff to postgres server
	if m.name == "postgres" && *cmd != "" {
		res := shell(&b, "Write")
		if len(res) != 0 {
			n = len(b) // make the caller think we wrote it all
			_, err = m.dst.Write(res)
			pq.Debug("We wrote this instead though")
			pq.DebugDump(res)
			return
		}
	}
	pq.DebugDump(b)
	n, err = m.dst.Write(b)

	pq.Debug("Write finished")
	return
}

// Read from dst src <- dst
func (m Mitm) Read(b []byte) (n int, err error) {
	n, err = m.dst.Read(b)
	f m.name == "psql" && *cmd != "" {
		in := b[:n]
		res := shell(&in, "Read")
		if len(res) != 0 {
			pq.Debug("replacing what we read from the client")
			b = []byte{}
			n = len(res)
			b = res
		}
	}
	if m.name == "psql" {
		pq.Debug("We read this from the client")
	} else {
		pq.Debug("We read this from the server")
	}
	pq.DebugDump(b[:n])
	pq.Debug("Read finished")

	return
}
*/

func main() {
	flag.Usage = Usage
	flag.Parse()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, os.Kill)
	clientCh := make(chan net.Conn)
	exit := make(chan struct{})

	var dburl *string

	if flag.NArg() == 1 {
		dburl = &flag.Args()[0]
		log.SetFlags(log.Lshortfile)
	} else {
		fmt.Println("try --help")
		return
	}

	p, err := url.Parse(*dburl)
	if err != nil || p.Scheme == "" {
		fmt.Printf("ERROR: (%s) url %s\n", err, p)
		return
	} else {
		p.Host = "127.0.0.1" + *port
		fmt.Println("NOTICE: use this url", p)
	}

	_, err = exec.LookPath(*cmd)
	if err != nil {
		fmt.Println(err)
		return
	}

	if *testquery != "" {
		db, err := sql.Open("postgres", *dburl)
		if err != nil {
			log.Fatal(err)
		}
		log.Println(db)
		drv, ok := db.Driver().(*pq.Drv)
		if ok {
			log.Println("YES", drv)
			log.Println(drv.More())
		}
		log.Println("db is", db)
		log.Println("running", *testquery)
		rows, err := db.Query(*testquery)
		if err != nil {
			log.Println(err)
		} else {
			//TODO make select anything work
			for rows.Next() {
				var email string
				if err := rows.Scan(&email); err != nil {
					log.Println(err)
					break
				}
			}
			rows.Close()
		}
		db.Close()
		log.Println("everything is closed")
		return
	}

	go func() {

		ln, err := net.Listen("tcp", *port)
		if err != nil {
			fmt.Println(err)
			exit <- struct{}{}
			return
		}
		for {
			conn, err := ln.Accept()
			if err != nil {
				pq.Debug("error", err)
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
				log.Println("Signal", s)
				break FOR
			case conn := <-clientCh:
				defer conn.Close()
				go func(conn net.Conn) {
					log.Println("got client conn", conn)
					m := new(pq.Mitm)
					m.Cmdname = cmd
					m.Client = conn
					_, err := pq.Open(*dburl, m)
					if err != nil {
						log.Println(err)
						return
					}
					go io.Copy(m, m.Client)
					io.Copy(m.Client, m)

				}(conn)
			default:
				//non-blocking
			}

		}
	}()
	<-exit
}
