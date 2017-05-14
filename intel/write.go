package ihex

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

type Writer struct {
	w     io.Writer
	width int
	addr  uint16
	fifo  bytes.Buffer
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
	var (
		originalXferLen int = len(p)
		xferLen         int
	)

	// Write caller's data to our internal FIFO
	x.fifo.Write(p)

	// Only write hex records 'width' wide.  Residual will be
	// held in the FIFO until a follow-up write(), a Flush() or
	// Writer is closed.
	for x.fifo.Len() >= x.width {
		err := x.emitDataRecord(x.fifo.Next(x.width))
		if err != nil {
			return xferLen, err
		}
		xferLen += x.width
	}

	return originalXferLen, nil
}

func (x *Writer) Flush() error {
	err := x.emitDataRecord(x.fifo.Next(x.fifo.Len()))
	if err != nil {
		return err
	}
	return nil
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
