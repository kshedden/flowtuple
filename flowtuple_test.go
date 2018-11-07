package flowtuple

import (
	"compress/gzip"
	"io"
	"log"
	"os"
	"testing"
)

func Test1(t *testing.T) {

	fid, err := os.Open("example.flowtuple.cors.gz")
	if err != nil {
		panic(err)
	}
	defer fid.Close()
	gid, err := gzip.NewReader(fid)
	if err != nil {
		panic(err)
	}
	defer gid.Close()

	lf, err := os.Create("Test1Log.txt")
	if err != nil {
		panic(err)
	}
	logger := log.New(lf, "", log.Ltime)

	ftr := NewFlowtupleReader(gid).SetLogger(logger)

	var frec FlowRec

	for {
		err := ftr.ReadIntervalHead()
		if err == io.EOF {
			break
		} else if err != nil {
			panic(err)
		}

		for {
			err := ftr.ReadClassHead()
			if err == io.EOF {
				break
			} else if err != nil {
				panic(err)
			}

			for {
				err := ftr.ReadRec(&frec)
				if err == io.EOF {
					break
				} else if err != nil {
					panic(err)
				}

				// Do something with frec
				//fmt.Printf("%v\n", frec)
			}

			err = ftr.ReadClassTail()
			if err == io.EOF {
				break
			} else if err != nil {
				panic(err)
			}
		}

		err = ftr.ReadIntervalTail()
		if err == io.EOF {
			break
		} else if err != nil {
			panic(err)
		}
	}
}
