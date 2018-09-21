package kit

import (
	"testing"
	"fmt"
)

func TestScanFile(t *testing.T){
	files,err := ScanFile("./")
	if err != nil{
		t.Error(err)
	}
	fmt.Println(files)
}
