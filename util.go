package main

import (
	"flag"
	"fmt"
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

func Error(i ...interface{}) {
	msg := _msg()
	var a []interface{}
	a = append(a, msg)
	a = append(a, i...)
	log.Println(a...)
}

func Fatal(i ...interface{}) {
	msg := _msg()
	var a []interface{}
	a = append(a, msg)
	a = append(a, i...)
	log.Fatal(a...)
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
