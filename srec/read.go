package srec

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
)

type srecType int

// Generalized form of a hex record
type HexRec struct {
	Address    uint32
	RecordType srecType
	Data       []byte
}

const (
	S_Unknown srecType = (iota - 1) // -1
	S0Header                        // 0
	S1Data                          // 1...
	S2Data                          //
	S3Data                          //
	_                               // S4 <-- Not defined in the standard
	S5Count
	S6Count
	S7Start
	S8Start
	S9Start
)

var srecTypeMap map[string]srecType
var srecStrMap map[srecType]string

func init() {
	srecTypeMap = make(map[string]srecType)
	srecStrMap = make(map[srecType]string)

	var srecEnums []srecType = []srecType{
		S0Header, S1Data, S2Data,
		S3Data, S5Count, S6Count,
		S7Start, S8Start, S9Start}

	for _, v := range srecEnums {
		s := fmt.Sprintf("S%d", v)
		srecTypeMap[s] = v
		srecStrMap[v] = s
	}
}

func (r HexRec) String() string {
	var s string

	header := srecStrMap[r.RecordType]
	if header == "" {
		header = "S?"
	}

	switch r.RecordType {
	case S0Header, S1Data, S5Count, S9Start: // 16-bit address cases
		s = fmt.Sprintf("Address: 0x%04X, Type: %s, Lenght: %d, content: %v",
			r.Address, header, len(r.Data), r.Data)

	case S2Data, S6Count, S8Start: // 24-bit address cases
		s = fmt.Sprintf("Address: 0x%06X, Type: %s, Lenght: %d, content: %v",
			r.Address, header, len(r.Data), r.Data)

	case S3Data, S7Start: // 32-bit address cases
		s = fmt.Sprintf("Address: 0x%08X, Type: %s, Lenght: %d, content: %v",
			r.Address, header, len(r.Data), r.Data)
	}

	return s
}

// Break the ASCII-Hex record up into fields; translate
// fields into appropriate binary values.
func decodeRecord(r string) (rec *HexRec, err error) {
	defer func() {
		if x := recover(); x != nil {
			err = fmt.Errorf("run time panic: %v", x)
		}
	}()

	var (
		address   string
		data      string
		checksum  string
		header    string   = r[:2]
		byteCount string   = r[2:4]
		recTyp    srecType = srecTypeMap[header]
		ovhd      int
		csData    string = r[2 : len(r)-2] // this is what will be checksum'd
	)

	switch recTyp {
	case S0Header, S1Data, S5Count, S9Start: // 16-bit address cases
		address = r[4:8]
		data = r[8:]
		ovhd = 2 + 1

	case S2Data, S6Count, S8Start: // 24-bit address cases
		address = r[4:10]
		data = r[10:]
		ovhd = 3 + 1

	case S3Data, S7Start: // 32-bit address cases
		address = r[4:12]
		data = r[12:]
		ovhd = 4 + 1

	default:
		return nil, errors.New("Unknown SREC type")
	}

	checksum, data = data[len(data)-2:], data[:len(data)-2]
	cs, err := strconv.ParseUint(checksum, 16, 8)
	if err != nil {
		return nil, err
	}

	csCalc, err := calcChecksumHexAscii(csData)
	if err != nil {
		return nil, err
	}
	if byte(cs) != csCalc {
		return nil, errors.New("Checksum error")
	}

	binData, err := hex.DecodeString(data)
	if err != nil {
		return nil, fmt.Errorf("Data chars bad: %s", err)
	}

	addrBin, err := strconv.ParseUint(address, 16, 32)
	if err != nil {
		return nil, fmt.Errorf("Address field error: %s", err)
	}

	bc, err := strconv.ParseUint(byteCount, 16, 8)
	if err != nil {
		return nil, fmt.Errorf("Byte-count field error: %s", err)
	}

	if int(bc) != (len(binData) + ovhd) {
		return nil, errors.New("byte-count error")
	}

	rec = new(HexRec)
	rec.Address = uint32(addrBin)
	rec.RecordType = recTyp
	rec.Data = binData

	return rec, nil
}

func processRecords(records []string) ([]*HexRec, error) {
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

func loadFile(fn string) ([]string, error) {
	content, err := ioutil.ReadFile(fn)
	if err != nil {
		return nil, err
	}

	records := strings.Split(string(content), "\n")

	return records, nil
}

func ReadFile(fn string) ([]*HexRec, error) {
	records, err := loadFile(fn)
	if err != nil {
		return nil, err
	}

	return processRecords(records)
}

// Merge contiguous blocks of data thus resulting in fewer records. All other
// record types are unaffected.  Contiguous data records are coalesced into
// a so-called "jumbo" data record.
func CoalesceDataRecs(list []*HexRec) []*HexRec {
	type handler func(*HexRec, srecType)
	var (
		dataRecGroup   bool = false
		addressCounter uint32
		outList        []*HexRec
		data           bytes.Buffer
		dataBaseAddr   uint32
		processDataRec handler
	)

	emitJumboDataRec := func(pt srecType) {
		var r HexRec
		r.Address = dataBaseAddr // Set Base Address
		r.RecordType = pt
		r.Data = data.Bytes()         // Set Data slice within record
		data.Reset()                  // Clear accumulation buffer
		outList = append(outList, &r) // Append record to output slice
	}

	processDataRec = func(r *HexRec, pt srecType) {
		if !dataRecGroup { // have we hit a new run of data recs?
			dataRecGroup = true
			dataBaseAddr = r.Address
			addressCounter = r.Address + uint32(len(r.Data))
			data.Reset()
			data.Write(r.Data)
		} else {
			if r.Address == addressCounter { // Contiguous with previous?
				data.Write(r.Data)
				addressCounter += uint32(len(r.Data))
			} else { // else, data records are not contiguous
				// Emit a Jumbo Data Record; reset temp buffer
				emitJumboDataRec(pt)
				dataRecGroup = false
				processDataRec(r, pt)
			}
		}
	}

	// Survey data record types
	var s1Count, s2Count, s3Count int
	for _, r := range list {
		switch r.RecordType {
		case S1Data:
			s1Count++
		case S2Data:
			s2Count++
		case S3Data:
			s3Count++
		}
	}

	// In case mixed data records were used in the original file,
	// determine which should be used for emitted jumbo records
	var preferredDataRecType srecType
	if s3Count > 0 {
		preferredDataRecType = S3Data
	} else if s2Count > 0 {
		preferredDataRecType = S2Data
	} else {
		preferredDataRecType = S1Data
	}

	// Cycle through all records looking specifically for data
	// records.
	for _, r := range list {
		switch r.RecordType {
		case S1Data, S2Data, S3Data:
			processDataRec(r, preferredDataRecType)

		default: // Other type found; terminate preceeding data group
			if data.Len() > 0 {
				emitJumboDataRec(preferredDataRecType)
			}
			dataRecGroup = false
			outList = append(outList, r)
		}
	}

	// Do we need to emit one last jumbo data record?
	if data.Len() > 0 {
		emitJumboDataRec(preferredDataRecType)
	}

	return outList
}
