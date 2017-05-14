package ihex

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// Writer implements an Intel Hex file writer
type Writer struct {
	w     io.Writer    // Underlying writer object
	width int          // Standard length for data records
	addr  uint16       // Address counter for data records
	fifo  bytes.Buffer // FIFO for writes
}

// NewWriterWidth creates a new Intel Hex writer with a specific data record length
func NewWriterWidth(w io.Writer, width int) *Writer {
	return &Writer{w: w, width: width}
}

// NewWriter Creates a new Intel Hex writer with a default length
func NewWriter(w io.Writer) *Writer {
	return NewWriterWidth(w, 16)
}

// SetAddress sets the data record base address within the writer
func (x *Writer) SetAddress(a uint16) {
	x.addr = a
}

// Emit generic data record
func (x *Writer) emitDataRecord(p []byte) error {
	// collect all the stuff that goes into this type of record
	var data = []interface{}{
		byte(len(p)), // byte count
		x.addr,       // standard 16-bit base address
		byte(Data),   // record type
		p,            // slice of data
	}

	err := x.emitRecord(data)
	if err != nil {
		return fmt.Errorf("emitDataRecord: %v", err)
	}

	x.addr += uint16(len(p))

	return nil
}

// Write if the idiomatic Go Write() method.  The size of p can be
// be up to 64K.
func (x *Writer) Write(p []byte) (int, error) {
	var (
		originalXferLen = len(p)
		xferLen         int
	)

	// Write caller's data to our internal FIFO
	x.fifo.Write(p)

	// Only write hex records 'width' wide.  Residual will be
	// held in the FIFO until a follow-up write(), Flush() or
	// Close() operation.
	for x.fifo.Len() >= x.width {
		err := x.emitDataRecord(x.fifo.Next(x.width))
		if err != nil {
			return xferLen, err
		}
		xferLen += x.width
	}

	return originalXferLen, nil
}

// Flush is used to write any Residual data within the FIFO to the
// output stream; the effect is a runt hex record written to the
// output stream.
func (x *Writer) Flush() error {
	if x.fifo.Len() > 0 {
		err := x.emitDataRecord(x.fifo.Next(x.fifo.Len()))
		if err != nil {
			return err
		}
	}
	return nil
}

// Close the output Stream.
// Note: the underlying io.Writer is NOT closed
func (x *Writer) Close() error {
	// Flush any residual data
	x.Flush()

	// Build up an EOF record
	var data = []interface{}{
		byte(0),   // byte count
		uint16(0), // standard 16-bit base address
		byte(1),   // record type (EOF)
	}

	// Write the EOF record; this will be the last
	// entity written to the stream.
	return x.emitRecord(data)
}

// Generic emit-record
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
		return fmt.Errorf("emitRecord: Failure formatting Intel Hex record: %v", err)
	}

	return nil
}

// WriteExSegAddr writes an Extended Segment Address record
func (x *Writer) WriteExSegAddr(sa uint16) error {
	// collect all the stuff that goes into this type of record
	var data = []interface{}{
		byte(2),          // byte count
		uint16(0),        // standard 16-bit base address
		byte(ExtSegAddr), // record type
		sa,               // caller's segment address
	}

	return x.emitRecord(data)
}

// WriteStartSegAddr writes a Start Segment Address record
func (x *Writer) WriteStartSegAddr(cs, ip uint16) error {
	// collect all the stuff that goes into this type of record
	var data = []interface{}{
		byte(4),            // byte count
		uint16(0),          // standard 16-bit base address
		byte(StartSegAddr), // record type
		cs,                 // 80x86 processor code segment value
		ip,                 // 80x86 processor IP register value
	}

	return x.emitRecord(data)
}

// WriteExtLinAddr writes an Extended Linear Address record
func (x *Writer) WriteExtLinAddr(ela uint16) error {
	// collect all the stuff that goes into this type of record
	var data = []interface{}{
		byte(2),          // byte count
		uint16(0),        // standard 16-bit base address
		byte(ExtLinAddr), // record type
		ela,              // upper 16-bits for all 00 type records
	}

	return x.emitRecord(data)
}

// WriteStartLinAddr writes a Start Extended Linear Address record
func (x *Writer) WriteStartLinAddr(eip uint32) error {
	// collect all the stuff that goes into this type of record
	var data = []interface{}{
		byte(4),            // byte count
		uint16(0),          // standard 16-bit base address
		byte(StartLinAddr), // record type
		eip,                // 32-bit value loaded into the EIP register
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
