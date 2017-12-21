package main

import (

	"github.com/jeffthorne/deepsecurity-go"
	_"fmt"

	"fmt"
)

func main(){

	//Eample #1: Authenticate against an on-prem DSM
	dsm, err := deepsecurity.NewDSM("admin", "password", "10.45.66.20", "4119", "", false)

	if err != nil{
		fmt.Println("Error Authenticating", err)
	}else{
		defer dsm.EndSession()
		fmt.Println("Autenticated successcully to DSM.")
	}

	//resp := dsm.HostGetStatus(9)
	//fmt.Printf("Status for host %s is %s.\n",resp.OverallStatus, resp.OverallStatus)
	//ids, err := dsm.HostRecommendationRuleIDsRetrieve(5205,2, "False")
	//if err != nil{
	//	log.Println("Error retrieving host:", err)
	//}else {
	//	fmt.Println(ids)
	//}
	//host := dsm.HostRetrieveByName("54.87.239.139")
	//fmt.Println(host.Name)


	///resp2 := dsm.HostDetailRetrieve(5205, 0, 0,"","HIGH")
	//fmt.Println("Lisht: ", resp2.ComponentKlasses.Item[0])

	//hostStatus := dsm.HostGetStatus(9)
	//fmt.Println(hostStatus.OverallStatus)
	//does not currently implement custom time ranges
	//timeType "LAST_HOUR", eventOperator="GREATER_THAN", eventID=1
	/*events := dsm.SystemEventRetrieve("LAST_HOUR", 4238, 0,  0, "SPECIFIC_HOST",
		                   1, true, "GREATER_THAN")
	fmt.Println("len", len(events))

	rule, err := dsm.DPIRuleRetrieve(4238)
	if err != nil{
		log.Println("Error retrieving host:", err)
	}else {
		fmt.Println(rule.Severity)


	resp := dsm.HostGroupRetrieveAll()

	for _, host := range resp{
		fmt.Println(host.ParentGroupID)
	}

		hostGroupID := int32(4201)
		hostIDs := []int32{5205,3001}




		dsm.HostMoveToHostGroup(hostIDs, hostGroupID)

*/
		//resp, _ := dsm.HostGroupCreate("test89", false, "", -1 )
		//fmt.Println(resp)

		hosts, err := dsm.HostRetrieveAll()
		//hosts, err := dsm.HostRetrieveByHostGroup(3)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println("Host len: ", len(hosts))
		for _, host := range hosts {
			fmt.Println(host.Name)
		}

	}

