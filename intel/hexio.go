package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

func checkErr(e error) {
	if e != nil {
		panic(e)
	}
}

type Writer struct {
	w     io.Writer
	width int
	addr  uint16
}

func NewWriterWidth(w io.Writer, width int) *Writer {
	var ihw Writer
	ihw.width = width
	ihw.w = w
	return &ihw
}

func NewWriter(w io.Writer) *Writer {
	return NewWriterWidth(w, 16)
}

func (x *Writer) SetAddress(a uint16) {
	x.addr = a
}

func (x *Writer) emitDataRecord(p []byte) error {
	// collect all the stuff that goes into this type of record
	var data = []interface{}{
		byte(len(p)), // byte count
		x.addr,       // standard 16-bit base address
		byte(0),      // record type
		p,            // slice of data
	}

	err := x.emitRecord(data)
	if err != nil {
		return fmt.Errorf("emitDataRecord: %v", err)
	}

	x.addr += uint16(len(p))

	return nil
}

func (x *Writer) Write(p []byte) (int, error) {
	b := p
	count := 0
	for w := len(b); w > 0; w = len(b) {
		if w >= x.width {
			err := x.emitDataRecord(b[0:x.width])
			if err != nil {
				return count, err
			}
			count += x.width
			b = b[x.width:] // snip the front off of b
		} else {
			err := x.emitDataRecord(b)
			if err != nil {
				return count, err
			}
			count += len(b)
			b = nil
		}
	}
	return count, nil
}

// Note: the underlying io.Writer is NOT closed
func (x *Writer) Close() error {
	// collect all the stuff that goes into this type of record
	var data = []interface{}{
		byte(0),   // byte count
		uint16(0), // standard 16-bit base address
		byte(1),   // record type (EOF)
	}

	// Write the Intel Hex EOF record; this should be the last
	// entity written to the stream
	return x.emitRecord(data)
	// Note: the underlying writer is _NOT_ closed; that is left
	// to the upper level code.
}

func (x *Writer) emitRecord(data []interface{}) error {
	buf := new(bytes.Buffer)

	// construct segment address record image
	for _, v := range data {
		err := binary.Write(buf, binary.BigEndian, v)
		if err != nil {
			return fmt.Errorf("Failure converting hex record to binary: %v", err)
		}
	}

	// append checksum
	err := buf.WriteByte(calcChecksum(buf.Bytes()))
	if err != nil {
		return fmt.Errorf("internal inconsistency writing to bytes.Buffer: %v", err)
	}

	s := strings.ToUpper(hex.EncodeToString(buf.Bytes()))
	_, err = fmt.Fprintf(x.w, ":%s\n", s)
	if err != nil {
		return fmt.Errorf("Failure formatting Intel Hex record: %v", err)
	}

	return nil
}

func (x *Writer) WriteExSegAddr(sa uint16) error {
	// collect all the stuff that goes into this type of record
	var data = []interface{}{
		byte(2),   // byte count
		uint16(0), // standard 16-bit base address
		byte(2),   // record type
		sa,        // caller's segment address
	}

	return x.emitRecord(data)
}

func (x *Writer) WriteStartSegAddr(cs, ip uint16) error {
	// collect all the stuff that goes into this type of record
	var data = []interface{}{
		byte(4),   // byte count
		uint16(0), // standard 16-bit base address
		byte(3),   // record type
		cs,        // 80x86 processor code segment value
		ip,        // 80x86 processor IP register value
	}

	return x.emitRecord(data)
}

// Write Extended Linear Address record
func (x *Writer) WriteExtLinAddr(addr uint16) error {
	// collect all the stuff that goes into this type of record
	var data = []interface{}{
		byte(2),   // byte count
		uint16(0), // standard 16-bit base address
		byte(4),   // record type
		addr,      // upper 16-bits for all 00 type records
	}

	return x.emitRecord(data)
}

// Write Start Extended Linear Address record
func (x *Writer) WriteStartLinAddr(eip uint32) error {
	// collect all the stuff that goes into this type of record
	var data = []interface{}{
		byte(4),   // byte count
		uint16(0), // standard 16-bit base address
		byte(5),   // record type
		eip,       // 32-bit value loaded into the EIP register
	}

	return x.emitRecord(data)
}

// Calculate checksum value based on Intel Hex Spec
func calcChecksum(buf []byte) byte {
	var cs int
	for _, b := range buf {
		cs += int(b)
	}
	return byte(-cs)
}

func main() {
	f, err := os.Create("foo.hex")
	checkErr(err)
	defer f.Close()

	w := NewWriter(f)
	defer w.Close()

	var data []byte = []byte("now is the time for all good men to come to the aid of their country; the quick brown fox jumps over the lazy dog.")

	w.Write(data)

	list, err := ReadFile("firmware.hex")
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Printf("%d hex records read\n", len(list))

	hexRecs := CoalesceDataRecs(list)

	fmt.Println("After coalescing...")

	fmt.Printf("%d hex records read\n", len(hexRecs))

	for l, r := range hexRecs {
		fmt.Printf("%d: %v\n", l+1, r)
	}
}

// READER...
// need to think about this...
type Descr struct {
	rtype byte   // record type (same as intel hex rec types
	base  uint16 // base address of binary data
	data  []byte // binary data
}

// Do sequences of contiguous data records need to be coalesced into a single
// run of bytes

type RecTyp byte

const (
	Data         RecTyp = 0x00
	EndOfFile    RecTyp = 0x01
	ExtSegAddr   RecTyp = 0x02
	StartSegAddr RecTyp = 0x03
	ExtLinAddr   RecTyp = 0x04
	StartLinAddr RecTyp = 0x05
	UnkTyp       RecTyp = 0xff
)

type HexRec struct {
	Address    uint16
	RecordType RecTyp
	Data       []byte
}

func (r HexRec) String() string {
	switch r.RecordType {
	case Data:
		return fmt.Sprintf("Address: 0x%04x, Type: Data, Data Length: %d",
			r.Address, len(r.Data))

	case EndOfFile:
		return fmt.Sprintf("Address: 0x%04x, Type: EOF, Data: %v",
			r.Address, r.Data)

	case ExtSegAddr:
		return fmt.Sprintf("Address: 0x%04x, Type: Extended Segment Address, Data: %v",
			r.Address, r.Data)

	case StartSegAddr:
		return fmt.Sprintf("Address: 0x%04x, Type: Start Segment Address, Data: %v",
			r.Address, r.Data)

	case ExtLinAddr:
		return fmt.Sprintf("Address: 0x%04x, Type: Extended Linear Address, Data: %v",
			r.Address, r.Data)

	case StartLinAddr:
		return fmt.Sprintf("Address: 0x%04x, Type: Start Linear Address, Data: %v",
			r.Address, r.Data)

	default:
		panic("Encountered unknown hex record type")
	}
}

func decodeRecord(s string) (*HexRec, error) {
	if s == "" {
		return nil, errors.New("Empty record detected")
	}

	// Remove the leading ':' character
	s = s[1:]

	// Convert the Hex-ASCII representation to binary
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("Unable to decode hex record: %s", err)
	}

	// Pop the checksum byte off the end
	checksum, b := b[len(b)-1], b[:len(b)-1]

	// Compare calculated checksum with actual
	if checksum != calcChecksum(b) {
		return nil, errors.New("Bad checksum detected")
	}

	// Create a new Hex Record
	hr := new(HexRec)
	var recLen byte

	// Create a sort of lookup table for fields to decode
	fields := []interface{}{
		&recLen,
		&hr.Address,
		&hr.RecordType,
	}

	// Set up a reader object for the binary-Reader
	buf := bytes.NewReader(b)

	// Decode record header fields
	for i, v := range fields {
		err := binary.Read(buf, binary.BigEndian, v)
		if err != nil {
			return nil, fmt.Errorf("Bad field #%d in hex record: %s", i+1, err)
		}
	}

	// Allocate a slice for the data bytes
	hr.Data = make([]byte, recLen)

	// Read data bytes into the above slice
	err = binary.Read(buf, binary.BigEndian, &hr.Data)
	if err != nil {
		return nil, fmt.Errorf("Bad data field in hex record: %s", err)
	}

	// Return a reference to the populated Hex Record
	return hr, nil
}

func ReadFile(fn string) ([]*HexRec, error) {
	content, err := ioutil.ReadFile(fn)
	checkErr(err)

	records := strings.Split(string(content), "\n")

	var hrecs []*HexRec
	for _, rec := range records {
		if len(rec) > 0 {
			hr, err := decodeRecord(rec)
			checkErr(err)
			hrecs = append(hrecs, hr)
		}
	}

	return hrecs, nil
}

// Merge contiguous blocks of data thus resulting in fewer records
func CoalesceDataRecs(list []*HexRec) []*HexRec {
	type handler func(r *HexRec)
	var (
		dataRecGroup   bool = false
		addressCounter uint16
		outList        []*HexRec
		data           bytes.Buffer
		dataBaseAddr   uint16
		processDataRec handler
	)

	emitJumboDataRec := func() {
		var newRec HexRec
		newRec.Address = dataBaseAddr      // Set Base Address
		newRec.RecordType = Data           // Set Record Tyoe == Data
		newRec.Data = data.Bytes()         // Set Data slice within record
		data.Reset()                       // Clear accumulation buffer
		outList = append(outList, &newRec) // Append record to output slice
	}

	processDataRec = func(r *HexRec) {
		if !dataRecGroup { // have we hit a new run of data recs?
			dataRecGroup = true
			dataBaseAddr = r.Address
			addressCounter = r.Address + uint16(len(r.Data))
			data.Reset()
			data.Write(r.Data)
		} else {
			if r.Address == addressCounter { // Contiguous with previous?
				data.Write(r.Data)
				addressCounter += uint16(len(r.Data))
			} else { // else, data records are not contiguous
				// Emit a Jumbo Data Record; reset temp buffer
				emitJumboDataRec()
				dataRecGroup = false
				processDataRec(r)
			}
		}
	}

	for _, rec := range list {
		if rec.RecordType == Data {
			processDataRec(rec)
		} else {
			if data.Len() > 0 {
				emitJumboDataRec()
			}
			dataRecGroup = false
			outList = append(outList, rec)
		}
	}

	// Check if we need to emit one last jumbo data record
	if data.Len() > 0 {
		emitJumboDataRec()
	}

	return outList
}
