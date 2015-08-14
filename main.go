package main

import (
    "bytes"
    "strings"
	"flag"
    "bufio"
    "regexp"
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
    "io/ioutil"
	"github.com/hagna/pqproxy/internal/pq"
	"database/sql"
)

var VERSION string

var dburl = flag.String("dburl", "", "url of database")
var port = flag.String("port", ":5432", "port on which to pose as server")
var cmd = flag.String("cmd", "", "stdin of cmd gets the bytes to read and stdout gives the bytes to write to postgres server")
var testquery = flag.String("t", "", "test query to try")
var pprof = flag.String("pprof", "", "turn on pprof by specifying an endpoint here like 127.0.0.1:6090")
var savetraffic = flag.String("txlog", "", "log all the connection traffic")
var refile = flag.String("refile", "", "file containing line separated \"regexp\" \"replacement\"")


func Usage() {
	fmt.Printf("Usage: ./pqproxy [options] postgres://[user]:[pass]@[host][:port]/[database]\n\n")
	flag.PrintDefaults()
}

func split(s string) ([]string, error) {
    j := -1
    // split up "asdfasdf\"asdfasdf\"" "bar bar bar"
    for i:=1; i<len(s); i++ {
        if s[i] == '"' {
            if s[i-1] != '\\' {
                j = i 
                break
            }
        }
    }
    if j == -1 {
        return nil, fmt.Errorf("could not parse %s try \"regexp\" \"substitution\"", s)
    }
    fmt.Println("s is", s, j)
    t1 := strings.Trim(s[1:j], `" `)
    t2 := strings.Trim(s[j+1:len(s)], `" `)
    res := []string{t1, t2}
    return res, nil
}

func mkregexp(s []byte) ([]pq.Sub, error) {
    res := []pq.Sub{}
    scanner := bufio.NewScanner(bytes.NewReader(s))
    for scanner.Scan() {
        line := scanner.Text()
        a, err := split(line)
        if err != nil {
            return nil, err
        }
        t_re := a[0]
        t_sub := []byte(a[1])
        r := regexp.MustCompile(t_re)
        res = append(res, pq.Sub{S: t_re, Re: r, Repl: t_sub})
    }
    return res, nil
}


func main() {
	flag.Usage = Usage
	flag.Parse()

    if *pprof != "" {
        go func() {
            log.Println(http.ListenAndServe(*pprof, nil))
        }()
    }
    var resubs []pq.Sub
    if *refile != "" {
        s, err := ioutil.ReadFile(*refile)
        if err != nil {
            fmt.Println(err)
            return
        }
        resubs, err = mkregexp(s)
        if err != nil {
            fmt.Println(err)
            return
        }
        fmt.Println("NOTICE: using these regsubs", resubs)
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
                m.Subs = resubs
                if *savetraffic != "" {
                    if err := m.OpenTxlog(*savetraffic); err != nil {
                        fmt.Println(err)
                        c <- os.Interrupt
                    }
                    defer m.CloseTxlog()
                    
                }
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
