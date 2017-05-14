package srec

import (
	"fmt"
	"strings"
	"testing"
)

func TestChecksumCalc(t *testing.T) {

	fmt.Println("TestChecksum()")

	x := "137AF00A0A0D00000000000000000000000000"
	cs, err := calcChecksumHexASCII(x)
	if err != nil {
		t.Fail()
	}

	if cs != 0x61 {
		t.Fail()
	}
}

func TestProcessRecords(t *testing.T) {

	fmt.Println("TestProcessRecords()")

	bulkSrec := `S00F000068656C6C6F202020202000003C
S11F00007C0802A6900100049421FFF07C6C1B787C8C23783C6000003863000026
S11F001C4BFFFFE5398000007D83637880010014382100107C0803A64E800020E9
S111003848656C6C6F20776F726C642E0A0042
S5030003F9
S9030000FC
`
	records := strings.Split(bulkSrec, "\n")

	hrecs, err := processRecords(records)

	if err != nil {
		fmt.Println("\t", err)
		t.Fail()
	}

	if len(hrecs) != 6 {
		fmt.Println("bad record count")
		t.Fail()
	}
}

func TestCoalesceDataRecs(t *testing.T) {
	fmt.Println("TestCoalesceDataRecs()")

	bulkSrec := `
S11F00007C0802A6900100049421FFF07C6C1B787C8C23783C6000003863000026
S111003848656C6C6F20776F726C642E0A0042
`
	records := strings.Split(bulkSrec, "\n")

	hrecs, err := processRecords(records)
	if err != nil {
		fmt.Println("\t", err)
		t.Fail()
	}

	if len(hrecs) != 2 {
		fmt.Println("expected 3 output records")
		t.Fail()
	}

	fmt.Printf("%d input records\n", len(hrecs))
	hrecs = CoalesceDataRecs(hrecs)

	if len(hrecs) != 2 {
		fmt.Printf("bulkSrec = %v\n", bulkSrec)
		fmt.Printf("hrecs=%v, len=%d\n", hrecs, len(hrecs))
		fmt.Println("expected only 1 record in result")
		t.Fail()
	}
}
