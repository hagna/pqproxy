package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
    "time"
	"os"
	"os/exec"
	"os/signal"
    _ "net/http/pprof"
    "net/http"

	"github.com/hagna/pqproxy/internal/pq"
	"database/sql"
)

var VERSION string

var dburl = flag.String("dburl", "", "url of database")
var port = flag.String("port", ":5432", "port on which to pose as server")
var cmd = flag.String("cmd", "", "stdin of cmd gets the bytes to read and stdout gives the bytes to write to postgres server")
var testquery = flag.String("t", "", "test query to try")
var pprof = flag.String("pprof", "", "turn on pprof by specifying an endpoint here like 127.0.0.1:6090")


func Usage() {
	fmt.Printf("Usage: ./pqproxy [options] postgres://[user]:[pass]@[host][:port]/[database]\n\n")
	flag.PrintDefaults()
}


func main() {
	flag.Usage = Usage
	flag.Parse()

    if *pprof != "" {
        go func() {
            log.Println(http.ListenAndServe(*pprof, nil))
        }()
    }

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

    if *dburl == "version" {
        fmt.Println(VERSION)
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

	if *cmd != "" {
		_, err = exec.LookPath(*cmd)
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	if *testquery != "" {
		db, err := sql.Open("postgres", *dburl)
		if err != nil {
			log.Fatal(err)
		}
		log.Println(db)
		drv, ok := db.Driver().(*pq.Drv)
		if ok {
			log.Println("YES we cast it to pq.Drv", drv)
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
				m := new(pq.Mitm)
				m.Cmdname = cmd
				m.Client = conn
				_, err := pq.Open(*dburl, m)
				if err != nil {
					log.Println(err)
					conn.Close()
					continue
				}
				defer m.Close()
				go func(m *pq.Mitm) {

					go io.Copy(m, m.Client)
					io.Copy(m.Client, m)
					m.Close()
				}(m)

    		default:
                time.Sleep(100 * time.Millisecond)
				//non-blocking
			}

		}
	}()
	<-exit
}
