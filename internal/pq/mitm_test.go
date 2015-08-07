package pq

import (
    "testing"
    )

func TestReplaceLen(t *testing.T) {
    q := "select * from table\x00"
    pref := "Q\x00\x00\x00\x00"
    fixit := []byte(pref + q)
    fixed := fixLen(fixit)
    t.Log("fix it it", fixit)
    r := readBuf(fixed)
    r.next(1)
    res := r.int32()
    expected := len([]byte(pref + q)) - 1 // but not Q
    if res != expected {
        t.Fatal("length was wrong received", res, fixed, "should have been", expected)
    }
}

func TestLen(t *testing.T) {
    q := "Q\x00\x00\x01\x01SELECT aaaaaaa_aaaa.aa_aaaa, aaaaaaa_aaaa.aaaaa, aaaaaaa_aaaa.aaaaaa_aa, aaaaaaa_aaaa.aaaaaaaaa, aaaaaaa_aaaa.aaaaaaaaa, aaaaaaa_aaaa.aa, aaaaaaa_aaaa.aaaaaaaa, aaaaaaa_aaaa.aaaaa, aaaaaaa_aaaa.aaaaa FROM aaaaaaa_aaaa WHERE aaaaaaa_aaaa.aa = 57 LIMIT 1\x00"
    r := readBuf(q)
    r.next(1)
    res := r.int32()
    expected := len([]byte(q)) - 1
    if res != expected {
        t.Fatalf("we got a length of %d instead of %d", res, expected)
    }
}

