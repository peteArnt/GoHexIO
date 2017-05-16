package srec

import (
	"fmt"
	"math/rand"
	"os"
	//	"strings"
	"reflect"
	"testing"
)

var binData []byte

func init() {
	binData = make([]byte, 16*1024)
	for i, _ := range binData {
		binData[i] = byte(rand.Int())
	}
}

func TestLoopback(t *testing.T) {
	fmt.Fprintln(os.Stdout, "Loopback test...")

	f, err := os.OpenFile("temp.srec", os.O_WRONLY, 0755)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failure creating temp file: %s\n", err)
		t.Fail()
	}

	w := NewWriter(f, Addr16)
	w.SetStartAddress(0x1000)
	w.SetAddress(0x1000)
	w.SetCountEmit()
	w.SetWidth(32)
	w.SetHeader([]byte("This is a Test File"))

	length, err := w.Write(binData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Write: %s\n", err)
		t.Fail()
	}
	if length != len(binData) {
		fmt.Fprintf(os.Stderr, "Bad length written\n")
		t.Fail()
	}
	w.Close()
	f.Close()

	recs, err := ReadFile("temp.srec")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failure reading srec file: %s\n", err)
		t.Fail()
	}

	recs = CoalesceDataRecs(recs)

	if !reflect.DeepEqual(recs[1].Data, binData) {
		fmt.Fprintln(os.Stderr, "failure: binary images differ")
		t.Fail()
	}

	fmt.Printf("%d records\n", len(recs))

}
