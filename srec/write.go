package srec

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// AddrMode is a data type used for Address Mode enumerations
type AddrMode int

// Address modes
const (
	Addr16 AddrMode = 16
	Addr24 AddrMode = 24
	Addr32 AddrMode = 32
)

// Writer implements the Motorola S-Record writer
type Writer struct {
	// State vars
	w     io.Writer    // Where to channel text output
	addr  uint32       // Address counter for writes
	count uint32       // count of S1/S2/S3 records emitted to write stream
	fin   bool         // Close() has been called
	tail  []byte       // post-fragment buffer
	fifo  bytes.Buffer // Used as internal Write FIFO

	// Configuration vars
	emitCountRec  bool     // Emit appropriate count record at file close
	emitStartRec  bool     // Emit Start Record at stream close
	startAddr     uint32   // Used for emitting Start Records S7/S8/S0
	addrMode      AddrMode // Address mode: 16, 24, or 32 bit addressing
	width         int      // bytes per line in SREC ourput
	header        []byte   // Header bytes
	headerEmitted bool
}

// NewWriter creates a new, default SREC writer
func NewWriter(w io.Writer, aMode AddrMode) *Writer {
	return &Writer{w: w, width: 10, addrMode: aMode}
}

// SetStartAddress enables emitting a Start Record as the terminating record before Close()
func (x *Writer) SetStartAddress(a uint32) {
	x.startAddr = a // used within an S7/S8/S9 record
	x.emitStartRec = true
}

// SetAddrMode sets the address mode within the writer
func (x *Writer) SetAddrMode(m AddrMode) {
	x.addrMode = m
}

// SetCountEmit enables the emition of a count record
func (x *Writer) SetCountEmit() {
	x.emitCountRec = true
}

// SetAddress sets the starting address for S1/S2/S3 records
func (x *Writer) SetAddress(a uint32) {
	x.Flush()
	x.addr = a
}

// SetHeader allows a custom header to be included in the resulting SREC file
func (x *Writer) SetHeader(h []byte) {
	x.header = h
}

func (x *Writer) emitHeaderRecord() error {
	var binBuf bytes.Buffer

	binBuf.WriteByte(byte(len(x.header)) + 3)
	binBuf.Write([]byte{0, 0})

	// Add data bytes, calculate checksum, append checksum to buffer
	binBuf.Write(x.header)
	binBuf.WriteByte(calcChecksum(binBuf.Bytes()))

	// Create ASCII representation w/record header
	asciiBuf := fmt.Sprintf("S0%s", hex.EncodeToString(binBuf.Bytes()))

	_, err := fmt.Fprintln(x.w, asciiBuf)
	if err != nil {
		return err
	}

	return nil
}

func (x *Writer) emitDataRecord(p []byte) error {
	var (
		binBuf bytes.Buffer
		recTyp byte
		addr   = bigEndianBin(x.addr)
	)

	switch x.addrMode {
	case Addr16:
		// Construct a binary image of the record so a checksum
		// can be calculated
		binBuf.WriteByte(byte(len(p)) + 3) // Length
		binBuf.Write(addr[2:])             // 16-bit address big endian
		recTyp = '1'

	case Addr24:
		// Construct a binary image of the record so a checksum
		// can be calculated
		binBuf.WriteByte(byte(len(p)) + 4) // Length
		binBuf.Write(addr[1:])             // 24-bit address big endian
		recTyp = '2'

	case Addr32:
		// Construct a binary image of the record so a checksum
		// can be calculated
		binBuf.WriteByte(byte(len(p)) + 4) // Length
		binBuf.Write(addr)                 // 32-bit address big endian
		recTyp = '3'
	}

	// Add data bytes, calculate checksum, append checksum to buffer
	binBuf.Write(p)
	binBuf.WriteByte(calcChecksum(binBuf.Bytes()))

	// Create ASCII representation w/record header
	asciiBuf := fmt.Sprintf("S%c%s", recTyp, hex.EncodeToString(binBuf.Bytes()))

	_, err := fmt.Fprintln(x.w, asciiBuf)
	if err != nil {
		return err
	}

	x.addr += uint32(len(p))
	x.count++

	return nil
}

func (x *Writer) emitCountRecord() error {
	var (
		binBuf  bytes.Buffer
		bigFile = (x.count > 65535)
		recTyp  byte
	)

	if bigFile {
		// length = 3 count + 1 checksum
		binBuf.WriteByte(3 + 1)
		c := bigEndianBin(x.count)
		binBuf.Write(c[1:])
		recTyp = '6'
	} else {
		// length = 2 count + 1 checksum
		binBuf.WriteByte(2 + 1)
		c := bigEndianBin(x.count)
		binBuf.Write(c[2:])
		recTyp = '5'
	}

	binBuf.WriteByte(calcChecksum(binBuf.Bytes()))

	// Create ASCII representation w/record header
	asciiBuf := fmt.Sprintf("S%c%s", recTyp, hex.EncodeToString(binBuf.Bytes()))

	_, err := fmt.Fprintln(x.w, asciiBuf)
	return err
}

func (x *Writer) emitStartAddrRec() error {
	var (
		binBuf bytes.Buffer
		recTyp byte
		addr   = bigEndianBin(x.startAddr)
	)

	const (
		recLen16 = 3
		recLen24 = 4
		recLen32 = 5
	)

	switch x.addrMode {
	case Addr16:
		// Construct a binary image of the record so a checksum
		// can be calculated
		binBuf.WriteByte(recLen16) // Length
		binBuf.Write(addr[2:])     // 16-bit address big endian
		recTyp = '9'

	case Addr24:
		// Construct a binary image of the record so a checksum
		// can be calculated
		binBuf.WriteByte(recLen24) // Length
		binBuf.Write(addr[1:])     // 24-bit address big endian
		recTyp = '8'

	case Addr32:
		// Construct a binary image of the record so a checksum
		// can be calculated
		binBuf.WriteByte(recLen32) // Length
		binBuf.Write(addr)         // 32-bit address big endian
		recTyp = '7'
	}

	// Add data bytes, calculate checksum, append checksum to buffer
	binBuf.WriteByte(calcChecksum(binBuf.Bytes()))

	// Create ASCII representation w/record header
	asciiBuf := fmt.Sprintf("S%c%s", recTyp, hex.EncodeToString(binBuf.Bytes()))

	_, err := fmt.Fprintln(x.w, asciiBuf)
	return err
}

// Write is the idiomatic Go write function used for writing blocks of data
// to a stream;
func (x *Writer) Write(p []byte) (int, error) {
	var (
		writeCount  int
		origXferLen = len(p)
	)

	// Has this writer already been closed?
	if x.fin {
		return 0, errors.New("Writer closed")
	}

	// Write out Header record if appropriate & this is THE first Write
	if (x.header != nil) && !x.headerEmitted {
		x.headerEmitted = true
		x.emitHeaderRecord()
	}

	// Write caller's data to an internal FIFO; there may be residual
	// bytes left over from a previous write.
	_, err := x.fifo.Write(p)
	if err != nil {
		return 0, err
	}

	// Write out as many full length data records as is possible
	for x.fifo.Len() >= x.width {
		err := x.emitDataRecord(x.fifo.Next(x.width))
		if err != nil {
			return writeCount, err
		}
		writeCount += x.width
	}

	return origXferLen, nil
}

// Flush writes any data remaining in the fifo to the output stream.
func (x *Writer) Flush() error {
	remaining := x.fifo.Len()
	if remaining > 0 {
		err := x.emitDataRecord(x.fifo.Next(remaining))
		if err != nil {
			return err
		}
	}
	return nil
}

// Close is used to flush any buffered data to the output stream and
// write potential termination record(s).
// Note: any underlying io.Writer will NOT closed here
func (x *Writer) Close() error {
	if x.fin {
		return errors.New("Writer already closed")
	}

	defer func() { x.fin = true }()

	err := x.Flush()
	if err != nil {
		return err
	}

	if x.emitCountRec {
		err := x.emitCountRecord()
		if err != nil {
			return err
		}
	}

	if x.emitStartRec { // terminating record for an SREC file
		err := x.emitStartAddrRec()
		if err != nil {
			return err
		}
	}

	return nil
}

// uint32 to []byte big-endian
func bigEndianBin(x uint32) []byte {
	var buf = make([]byte, 4)
	buf[0] = byte(x >> 24)
	buf[1] = byte(x >> 16)
	buf[2] = byte(x >> 8)
	buf[3] = byte(x)
	return buf
}
