package pq

import (
	"bytes"
    "regexp"
    "crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
    "os"
	"os/exec"
    "encoding/binary"
)

var server_version = flag.String("sver", "10.0.0", "Version number to pass to the client")
var cert = flag.String("cert", "", "Cert for ssl auth to client")
var key = flag.String("key", "", "Key for ssl auth to client")

// This is for intercepting writes to the postgres database and altering them in transit.
type Mitm struct {
	net.Conn          // this is the postgres server
	Client   net.Conn // the postgres client psql or a webserver
	Cmdname  *string
    Subs []Sub
    params [][]byte
    txlog *os.File
}

// This for holding the rewrite regular expressions
type Sub struct {
    S string // the regular expression before compilation
    Re *regexp.Regexp // compiled regexp
    Repl []byte // the replacement 
}

func (m *Mitm) OpenTxlog(fname string) (err error) {
    s := fmt.Sprintf("%s_%s", fname, m.Client.RemoteAddr())
    m.txlog, err = os.Create(s)
    if err != nil {
        return err
    }
    return nil
}

func (m *Mitm) CloseTxlog() {
    m.txlog.Close()
}

func (m *Mitm) savetraffic(b []byte) {
    if m.txlog != nil {
        _, err := m.txlog.Write(b)
        if err != nil {
            Debug(err)
        }
    }
}

const (
    WRITESERVER = "ws"
    READSERVER = "rs"
    WRITECLIENT = "wc"
    READCLIENT = "rc"
)

func (m *Mitm) Write(b []byte) (n int, err error) {
	Debug("WRITE")
    if len(m.Subs) > 0 {
        for _, sub := range m.Subs {
            if sub.Re.Match(b) {
                nb := sub.Re.ReplaceAll(b, sub.Repl)
                nb = fixLen(nb)
                n = len(b)
                _, err = m.Conn.Write(nb)
                m.savetraffic(nb)
                Debug("REGEXP INTERCEPT")
                DebugDump(nb)
                return
            }
        }
    } else if b[0] == 'Q' {
        if *m.Cmdname != "" {
            res := m.shell(&b, WRITESERVER)
            if len(res) != 0 {
                n = len(b) // make the caller think we wrote it all
                res = fixLen(res)
                m.savetraffic(res)
                _, err = m.Conn.Write(res)
                Debug("INTERCEPT")
                DebugDump(res)
                return
            }
        }
    }
	n, err = m.Conn.Write(b)
    m.savetraffic(b)
	DebugDump(b[:n])
	return
}

func (m *Mitm) Read(b []byte) (n int, err error) {
	n, err = m.Conn.Read(b)
	if err != nil {
		Debug(err)
	} else {
		Debug("READ", n)
        if *m.Cmdname != "" {
            res := m.shell(&b, READSERVER)
            if len(res) != 0 {
                n = len(res)
                b = res
                Debug("READ INTERCEPT")
                DebugDump(res)
                m.savetraffic(b)
                return
            }
        }
	}
    m.savetraffic(b)
	DebugDump(b[:n])
	return
}

func (m Mitm) shell(b *[]byte, name string) []byte {
	cmd := exec.Command(*m.Cmdname, name)
	cmd.Stdin = bytes.NewReader(*b)
	res, err := cmd.CombinedOutput()
	if err != nil {
		Debug(string(res))
		Debug(err)
	}
	return res
}

func (m Mitm) Close() error {
	var err error
	if m.Conn != nil {
		Debug("Close()", m.Conn.RemoteAddr())
		err = m.Conn.Close()
		if err != nil {
			log.Println(err)
		}
	}
	if m.Client != nil {
		Debug("Close()", m.Client.RemoteAddr())
		err = m.Client.Close()
		if err != nil {
			log.Println(err)
		}
	}
	return err
}

func readN(client net.Conn, n int) {
	Debug("reading", n, "from", client.RemoteAddr())
	b := make([]byte, n)
	n, e := client.Read(b[:])
	if e != nil {
		Debug(e)
	}
	DebugDump(b[:n])
}

func sendReady(client net.Conn) {
	wb := writeBuf([]byte{})
	wb.byte('Z')
	wb.int32(5)
	wb.byte('i')
	n, err := client.Write([]byte(wb))
	if err != nil {
		Debug(err, "trying to send readyforquery")
	} else {
		Debug("sent readyforquery to client", wb, n, err)
	}
}

func sendAuthPlain(client net.Conn) {
	wb := writeBuf([]byte{})
	wb.byte('R')
	wb.int32(8)
	wb.int32(3)
	n, err := client.Write([]byte(wb))
	if err != nil {
		Debug(err, "trying to send AuthClearTextPassword")
	} else {
		Debug("sent AuthenticationCleartextPassowrd to client", wb, n, err)
	}
}

func sendAuthMd5(client net.Conn) {
	wb := writeBuf([]byte{})
	wb.byte('R')
	wb.int32(23)
	wb.int32(5)
	for i := 0; i < 4; i++ {
		wb.byte('A')
	}
	n, err := client.Write([]byte(wb))
	if err != nil {
		Debug(err, "trying to send sendAuthMd5")
	} else {
		Debug("sent sendAuthMd5 to client", wb, n, err)
	}
}

func sendAuthOk(client net.Conn) {
	wb := writeBuf([]byte{})
	wb.byte('R')
	wb.int32(8)
	wb.int32(0)
	n, err := client.Write([]byte(wb))
	if err != nil {
		Debug(err, "trying to send AuthenticationOk")
	} else {
		Debug("sent AuthenticationOk to client", wb, n, err)
	}
}

func addParam(wb *writeBuf, k, v string) {
	l := len(k) + len(v) + 2 + 4  // the message looks like Byte1('S') Int32 String, so 4 is for Int32 and 2 is for 'S' and null terminated string
	wb.int32(l)
	wb.string(k)
	wb.string(v)
}

func (m *Mitm) queueParameter(r []byte) {
    if m == nil {
        Debug("m is nil bailing though I was sent this:")
        DebugDump(r)
        return
    }
    DebugDump(r)
    wb := writeBuf([]byte("S"))
    wb.int32(len(r) + 4)
    wb.bytes(r)
    Debug("writebuf")
    DebugDump(wb)
    m.params = append(m.params, []byte(wb))
    
}

func (m *Mitm) sendClientParams() {
    for _, wb := range m.params {
        DebugDump(wb)
        _, err := m.Client.Write([]byte(wb))
        if err != nil {
            Debug(err)
        }
    }
}

func sendParameter(client net.Conn, k, v string) {
	wb := writeBuf([]byte{})
	wb.byte('S')
	addParam(&wb, k, v)
	_, err := client.Write([]byte(wb))
	if err != nil {
		Debug(err, "trying to send parameter", k, v)
	} else {
		Debug("sent Parameter", k, v)
        DebugDump(wb)
	}
}

// given a query message which is Byte1('Q') Int32 String fix the length (Int32) field, so the underlying script won't have to
// http://www.postgresql.org/docs/9.2/static/protocol-message-formats.html
func fixLen(fixme []byte) []byte {
    l := (len(fixme) - 1)  // skip the Q in "Q\x00\x00\x01\x01SELECT..."
    binary.BigEndian.PutUint32(fixme[1:], uint32(l))
    return fixme
}


func doTLS(client net.Conn, cert, key string) (net.Conn, error) {
    certpem, err := tls.LoadX509KeyPair(cert, key)
            if err != nil {
                return nil, err
            }
    c := new(tls.Config)
    c.Certificates = []tls.Certificate{certpem}
    c.ClientAuth = tls.VerifyClientCertIfGiven
    c.ServerName = "foobar.com"
    tlsConn := tls.Server(client, c)
    Debug("about to do TLS handshake")
    if err = tlsConn.Handshake(); err != nil {
        return nil, err
    } 
    return tlsConn, nil
}

// This is for making the cient think it is connected to a real postgres
// server.
func (m *Mitm) startup() error {
	connstr := fmt.Sprintf("%s %s <-> %s %s", m.Client.RemoteAddr(), m.Client.LocalAddr(), m.Conn.LocalAddr(), m.Conn.RemoteAddr())
	Debug("--------- BEGIN STARTUP for", connstr)
	bc := [100]byte{}
	client := m.Client
	n, _ := client.Read(bc[:])
	rb := readBuf(bc[:n])
	rbi := rb.int32()
	rbi = rb.int32()
	if rbi == 80877103 {
		client := m.Client
        if *cert != "" && *key != "" {
            
            _, err := client.Write([]byte{'S'})
            if err != nil {
                Debug("ERROR sending we support ssl")
            }
            Debug("Did the client respond to the S?")
            m.Client, err = doTLS(client, *cert, *key)
            if err != nil {
                Debug("ERROR in doTLS", err)
            }
            readN(m.Client, 100)

        } else {
		    Debug("The client wants ssl, but we're going to say we don't support it", rbi)
            _, _ = client.Write([]byte{'N'})
            readN(client, 1024)
        }

	}
	/* The right order is this, but it isn't required
	   sendAuthPlain(client)
	   readN(client, 100)
	*/
	sendAuthOk(m.Client)
    m.sendClientParams()
	//sendParameter(client, "client_encoding", "UTF8")
	//sendParameter(client, "server_version", *server_version)
	sendReady(client)
	Debug("--------- END STARTUP for", connstr)
	log.Println("client startup complete")
    return nil
}
