package main

import (
	"fmt"
	"github.com/jeffthorne/deepsecurity-go"
)

func main(){

	//Authenticate against an on-prem DSM
	dsm := deepsecurity.NewDSM("username", "password", "192.168.8.12", "4119", "", false)
	fmt.Println(dsm.SessionID)
	dsm.EndSession()

	dsm = deepsecurity.NewDSM("username", "password", "", "", "ACME Corp", true)
	fmt.Println(dsm.SessionID)
	dsm.EndSession()
}