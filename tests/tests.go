package main

import (
	"github.com/jeffthorne/deepsecurity-go"
	"fmt"
)

func main(){
	dsm, err := deepsecurity.NewDSM("masteradmin", "trendmicro", "10.45.66.20", "4119", "", false)

	if err != nil{
		fmt.Println("Error found: ", err)
	}else{
		defer dsm.EndSession()
		fmt.Println(dsm.SessionID)
		dsm.HostClearWarningsErrors([]int32{33,35})

		hostStatus, err := dsm.HostGetStatus(33)

		if err != nil{
			fmt.Println(err)
		}else{
			fmt.Println(hostStatus)
		}


	}



}