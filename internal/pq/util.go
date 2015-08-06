package pq

import (
	"flag"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"log"
	"runtime"
	"strings"
)

var verbose = flag.Int("v", 0, "verbose?")

func _msg() string {
	var msg string
	if _, fname, lineno, ok := runtime.Caller(2); !ok {
		msg = "couldn't get line number"
	} else {
		j := strings.LastIndex(fname, "/")
		fname = fname[j+1:]
		msg = fmt.Sprintf("./%s:%d ", fname, lineno)
	}
	return msg
}

func Fatal(i ...interface{}) {
	msg := _msg()
	var a []interface{}
	a = append(a, msg)
	a = append(a, i...)
	log.Fatal(a...)
}

func Fatalf(format string, i ...interface{}) {
	msg := _msg()
	log.Fatalf(msg+format, i...)
}

func Debug(i ...interface{}) {
	if *verbose > 0 {
		msg := _msg()
		fmt.Printf(msg)
		fmt.Println(i...)
	}
}

func Debugf(format string, i ...interface{}) {
	if *verbose > 0 {
		msg := _msg()
		fmt.Printf(msg+format, i...)
	}
}

func Info(i ...interface{}) {
	msg := _msg()
	fmt.Printf(msg)
	fmt.Println(i...)

}

func DebugDump(i ...interface{}) {
	if *verbose > 0 {
		msg := _msg()
		fmt.Printf(msg)
		spew.Dump(i...)
	}
}
