package main

import "C"

import (
	"time"

	bpf "github.com/aquasecurity/libbpfgo"
)

func main() {

	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	defer bpfModule.Close()
	if err != nil {
		panic(err)
	}

	prog, err := bpfModule.GetProgram("my_program")
	if err != nil {
		panic(err)
	}
	prog.SetAutoload(true)
	prog.Unload()
	bpfModule.BPFLoadObject()
	time.Sleep(time.Second * 4)

}
