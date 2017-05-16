package ihex

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
)

// RecTyp indicates the type of Intel Hex record
type RecTyp byte

// Enumerated hex record types
const (
	Data         RecTyp = iota // 00
	EndOfFile                  // 01
	ExtSegAddr                 // 02
	StartSegAddr               // 03
	ExtLinAddr                 // 04
	StartLinAddr               // 05
)

var recTypeStr = map[RecTyp]string{
	Data:         "Data",
	EndOfFile:    "EOF",
	ExtSegAddr:   "Extended Segment Address",
	StartSegAddr: "Start Segment Address",
	ExtLinAddr:   "Extended Linear Address",
	StartLinAddr: "Start Linear Address",
}

// HexRec is an abstract hex record
type HexRec struct {
	Address    uint16
	RecordType RecTyp
	Data       []byte
}

func (r HexRec) String() string {
	return fmt.Sprintf("Address: 0x%04x, Type: %s, Data: %v",
		r.Address, recTypeStr[r.RecTyp], r.Data)
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

// ReadFile reads a hex file specified by fn and returns a slice of
// pointers to HexRec. If error is non-nil, it will indicate an
// issue reading the hex file or parsing a hex record.
func ReadFile(fn string) ([]*HexRec, error) {
	content, err := ioutil.ReadFile(fn)
	if err != nil {
		return nil, err
	}

	records := strings.Split(string(content), "\n")

	var hrecs []*HexRec
	for _, rec := range records {
		if len(rec) > 0 {
			hr, err := decodeRecord(rec)
			if err != nil {
				return nil, err
			}
			hrecs = append(hrecs, hr)
		}
	}

	return hrecs, nil
}

// CoalesceDataRecs merges contiguous runs of data records
func CoalesceDataRecs(list []*HexRec) []*HexRec {
	type handler func(r *HexRec)
	var (
		dataRecGroup   bool
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
