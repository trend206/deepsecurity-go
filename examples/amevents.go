package main

import (
	"github.com/jeffthorne/deepsecurity-go"
	"fmt"
	"time"

)


func main() {

	// Authenticate against DsaS
	dsm, err := deepsecurity.NewDSM("username", "Password1!", "127.0.0.1", "4119", "", false)
	if err != nil {
		fmt.Println("Error Authenticating", err)
	} else {
		defer dsm.EndSession()
		fmt.Println("Authenticated successcully to DSM.")

		events, err := dsm.AntiMalwareEventRetrieveByHost(time.Now(), time.Now().Add(-15 * time.Hour), time.Time{}, "LAST_HOUR", 46, 0,
			0, "SPECIFIC_HOST", 1, "GREATER_THAN")

		if err != nil {
			fmt.Println(err)
		} else if events != nil{
			fmt.Printf("%d events found.\n", len(events))
		}else{
			fmt.Println("No AM events found")
		}
	}


	t := time.Now()
	fmt.Println(t.Format("2006-01-02 15:04:05.99999"))
}

