package main

import (
	"github.com/trend206/deepsecurity-go"
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

		//Example 1: Retrieve Events by Time Range
		events, err := dsm.SystemEventRetrieve(time.Now().Add(-24*time.Hour), time.Now(), time.Time{}, "CUSTOM_RANGE", 24, 0,
			0, "SPECIFIC_HOST", 1, "GREATER_THAN", true)

		if err != nil {
			fmt.Println(err)
		} else if events != nil {
			fmt.Printf("%d events found by custom time range.\n", len(events))
		} else {
			fmt.Println("No System Events events found")
		}


		//Example 2: Retrieve Events by Specific Time. Note I have yet to get this working or System Events not sure of time accuracy requirements.
		pastDate := time.Date(2017, time.December, 29, 13, 45, 47, 000, time.UTC)
		events, err = dsm.SystemEventRetrieve(time.Time{}, time.Time{}, pastDate, "SPECIFIC_TIME", 24, 0,
			0, "SPECIFIC_HOST", 1, "GREATER_THAN", true)

		if err != nil {
			fmt.Println(err)
		} else if events != nil {
			fmt.Printf("%d events found by specific time.\n", len(events))
		} else {
			fmt.Println("No System Events events found by specific time.")
		}


		//Example 2: Retrieve Events by time range
		events, err = dsm.SystemEventRetrieve(time.Time{}, time.Time{}, time.Time{}, "LAST_24_HOURS", 24, 0,
			0, "HOSTS_IN_GROUP", 1, "GREATER_THAN", true)

		if err != nil {
			fmt.Println(err)
		} else if events != nil {
			fmt.Printf("%d events found by set time range.\n", len(events))
		} else {
			fmt.Println("No System Events events found")
		}



		//Example 2: Retrieve Events by Host Group
		events, err = dsm.SystemEventRetrieve(time.Time{}, time.Time{}, time.Time{}, "LAST_24_HOURS", 0, 4,
			0, "HOSTS_IN_GROUP", 1, "GREATER_THAN", true)

		if err != nil {
			fmt.Println(err)
		} else if events != nil {
			fmt.Printf("%d events found by host group.\n", len(events))
		} else {
			fmt.Println("No System Events events found")
		}


		//Example 2: Retrieve Events by Security Policy
		events, err = dsm.SystemEventRetrieve(time.Time{}, time.Time{}, time.Time{}, "LAST_24_HOURS", 0, 0,
			13, "HOSTS_USING_SECURITY_PROFILE", 1, "GREATER_THAN", true)

		if err != nil {
			fmt.Println(err)
		} else if events != nil {
			fmt.Printf("%d events found by security policy.\n", len(events))
		} else {
			fmt.Println("No System Events events found")
		}

	}


}

