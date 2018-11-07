// Package flowtuple reads binary flowtuple files.  The records of
// the flowtuple file can be read sqeuentieally into Go structs.
//
// The flowtuple file format is documented here:
//
// http://www.caida.org/tools/measurement/corsaro/docs/formats.html

package flowtuple

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
)

type FlowtupleReader struct {

	// Read flowtuples from this file
	r io.Reader

	// Current interval
	inum int

	// Current class id
	classid int

	// Current key count
	keycnt int

	// Number of current record
	recnum int

	// Write log to this file
	logger *log.Logger
}

func (ftr *FlowtupleReader) ClassId() int {
	return ftr.classid
}

func (ftr *FlowtupleReader) Inum() int {
	return ftr.inum
}

func NewFlowtupleReader(r io.Reader) *FlowtupleReader {

	return &FlowtupleReader{
		r: r,
	}
}

func (ftr *FlowtupleReader) SetLogger(logger *log.Logger) *FlowtupleReader {
	ftr.logger = logger
	return ftr
}

// FlowRec contains one record in a flowtuple file.
type FlowRec struct {

	// Source IP address
	SrcIP uint32

	// Destination IP address
	DstIP uint32

	// Source port number
	SrcPort uint16

	// Destination port number
	DstPort uint16

	// Protocol
	Protocol uint8

	// Flags
	Flags uint8

	Ttl uint8

	// Packet size
	IPLen uint16

	// Number of packets
	Count uint32

	strval string
	buf    []byte
}

// ReadFrom reads a record from a flowtuple file into the flowrec struct.
func (fr *FlowRec) ReadFrom(gid io.Reader) error {

	if len(fr.buf) == 0 {
		fr.buf = make([]byte, 4)
	}

	binary.Read(gid, binary.BigEndian, &fr.SrcIP)

	for k := 0; k < 4; k++ {
		fr.buf[k] = 0
	}
	n, err := gid.Read(fr.buf[1:4])
	if err != nil {
		return err
	}
	if n != 3 {
		return fmt.Errorf("Incomplete read")
	}
	binary.Read(bytes.NewReader(fr.buf), binary.BigEndian, &fr.DstIP)

	binary.Read(gid, binary.BigEndian, &fr.SrcPort)
	binary.Read(gid, binary.BigEndian, &fr.DstPort)
	binary.Read(gid, binary.BigEndian, &fr.Protocol)
	binary.Read(gid, binary.BigEndian, &fr.Flags)
	binary.Read(gid, binary.BigEndian, &fr.Ttl)
	binary.Read(gid, binary.BigEndian, &fr.IPLen)
	binary.Read(gid, binary.BigEndian, &fr.Count)

	return nil
}

// fmtIP formats an IP address as a string.
func fmtIP(x uint32) string {

	var y [4]uint8
	for j := 0; j < 4; j++ {
		y[j] = uint8(x % 256)
		x /= 256
	}

	var b bytes.Buffer
	for j := 0; j < 4; j++ {
		b.Write([]byte(fmt.Sprintf("%d", y[3-j])))
		if j < 3 {
			b.Write([]byte("."))
		}
	}

	return b.String()
}

// String provides a string representation of a flowtuple record.
func (fr FlowRec) String() string {

	var b bytes.Buffer

	b.Write([]byte(fmt.Sprintf("%s|", fmtIP(fr.SrcIP))))
	b.Write([]byte(fmt.Sprintf("%s|", fmtIP(fr.DstIP))))
	b.Write([]byte(fmt.Sprintf("%d|", fr.SrcPort)))
	b.Write([]byte(fmt.Sprintf("%d|", fr.DstPort)))
	b.Write([]byte(fmt.Sprintf("%d|", fr.Protocol)))
	b.Write([]byte(fmt.Sprintf("%d|", fr.Flags)))
	b.Write([]byte(fmt.Sprintf("%#x|", fr.Ttl)))
	b.Write([]byte(fmt.Sprintf("%d|", fr.IPLen)))
	b.Write([]byte(fmt.Sprintf("%d", fr.Count)))

	return b.String()
}

func (ftr *FlowtupleReader) ReadIntervalHead() error {

	// Should be magic number 0x45444752
	var magic uint32
	err := binary.Read(ftr.r, binary.BigEndian, &magic)
	if err != nil {
		return err
	}
	if magic == 0 {
		// Not documented, but magic=0 seems to end the file
		return io.EOF
	} else if magic != 0x45444752 {
		return fmt.Errorf("Incorrect magic number %x\n", magic)
	}

	// Should be interval magic number 0x494E5452
	err = binary.Read(ftr.r, binary.BigEndian, &magic)
	if err != nil {
		return err
	}
	if magic != 0x494e5452 {
		return fmt.Errorf("Incorrect magic number %x\n", magic)
	}

	var inum uint16
	err = binary.Read(ftr.r, binary.BigEndian, &inum)
	if err != nil {
		panic(err)
	}
	if ftr.logger != nil {
		ftr.logger.Printf("Interval number: %v\n", inum)
	}
	ftr.inum = int(inum)

	var istart uint32
	err = binary.Read(ftr.r, binary.BigEndian, &istart)
	if err != nil {
		return err
	}
	if ftr.logger != nil {
		ftr.logger.Printf("Interval start time: %v\n", istart)
	}

	return nil
}

func (ftr *FlowtupleReader) ReadClassHead() error {

	// Should be flowtuple magic 0x53495854
	var magic uint32
	err := binary.Read(ftr.r, binary.BigEndian, &magic)
	if err != nil {
		panic(err)
	}
	if magic == 0x45444752 {
		// Done with this interval
		return io.EOF
	} else if magic != 0x53495854 {
		return fmt.Errorf("Incorrect magic: %x\n", magic)
	}

	var classid uint16
	err = binary.Read(ftr.r, binary.BigEndian, &classid)
	if err != nil {
		return err
	}
	if ftr.logger != nil {
		ftr.logger.Printf("Class id: %v\n", classid)
	}
	ftr.classid = int(classid)

	var keycnt uint32
	err = binary.Read(ftr.r, binary.BigEndian, &keycnt)
	if err != nil {
		return err
	}
	if ftr.logger != nil {
		ftr.logger.Printf("Key count: %v\n", keycnt)
	}
	ftr.keycnt = int(keycnt)

	ftr.recnum = 0

	return nil
}

// Read one record from a flowtuple file.
func (ftr *FlowtupleReader) ReadRec(frec *FlowRec) error {
	if ftr.recnum >= ftr.keycnt {
		return io.EOF
	}
	err := frec.ReadFrom(ftr.r)
	if err != nil {
		return err
	}
	ftr.recnum++
	return nil
}

func (ftr *FlowtupleReader) ReadClassTail() error {

	var magic uint32
	err := binary.Read(ftr.r, binary.BigEndian, &magic)
	if err != nil {
		panic(err)
	}
	if magic != 0x53495854 {
		return fmt.Errorf("Incorrect magic number %x", magic)
	}

	var classid2 uint16
	err = binary.Read(ftr.r, binary.BigEndian, &classid2)
	if err != nil {
		return err
	}
	if int(classid2) != ftr.classid {
		return fmt.Errorf("Incorrect class id: %d != %d", ftr.classid, classid2)
	}

	return nil
}

func (ftr *FlowtupleReader) ReadIntervalTail() error {

	// Should be interval magic number 0x494E5452
	var magic uint32
	err := binary.Read(ftr.r, binary.BigEndian, &magic)
	if err != nil {
		return err
	}
	if magic != 0x494e5452 {
		return fmt.Errorf("Incorrect magic number %x\n", magic)
	}

	var inum2 uint16
	err = binary.Read(ftr.r, binary.BigEndian, &inum2)
	if err != nil {
		return err
	}
	if ftr.logger != nil {
		ftr.logger.Printf("Interval number: %v\n", inum2)
	}
	if int(inum2) != ftr.inum {
		return fmt.Errorf("Incorrect interval number%d !=  %d", ftr.inum, inum2)
	}

	var iend uint32
	err = binary.Read(ftr.r, binary.BigEndian, &iend)
	if err != nil {
		return err
	}
	if ftr.logger != nil {
		ftr.logger.Printf("Interval end time: %v\n", iend)
	}

	return nil
}
