// package deepsecurity provides a DSM struct to interface with Deep Security's REST and SOAP APIs
package deepsecurity

import (
	"crypto/tls"
	"github.com/jeffthorne/deepsecurity-go/gowsdlservice"
	"fmt"
	"log"
	"net/http"
	"github.com/levigross/grequests"
	"errors"
)


var dsasHost string = "app.deepsecurity.trendmicro.com"
var dsasPort string = "443"


type DSM struct {
	SessionID  string
	Host       string
	Port       string
	Tenant     string
	RestURL    string
	RestClient http.Client
	SoapClient *gowsdlservice.Manager
	SoapURL    string
}


// NewDSM is used to obtain a DSM struct.
// return empty DSM struct if there was a problem with communication or auth.
func NewDSM(username string, password string, host string, port string, tenant string, verifySSL bool) (DSM, error) {
	dsm := DSM{Host: host, Port: port, Tenant: tenant}
	if dsm.Host == "" {
		dsm.Host = dsasHost
		dsm.Port = dsasPort
	}

	dsm.RestURL = fmt.Sprintf("https://%s:%s/rest/", dsm.Host, dsm.Port)
	dsm.SoapURL = fmt.Sprintf("https://%s:%s/webservice/Manager", dsm.Host, dsm.Port)
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: !verifySSL}}
	dsm.RestClient = http.Client{Transport: tr}
	sessionID, err := authenticate(username, password, &dsm, verifySSL)

	if err != nil{
		return DSM{}, err
	}else{
		dsm.SessionID = sessionID
		return dsm, nil
	}
}

func authenticate(username string, password string, dsm *DSM, verifySSL bool) (string, error) {

	var str string
	auth := gowsdlservice.BasicAuth{Login: username, Password: password}
	dsm.SoapClient = gowsdlservice.NewManager(dsm.SoapURL, true, &auth)

	if dsm.Tenant != "" {
		tenantAuth := gowsdlservice.AuthenticateTenant{TenantName: dsm.Tenant, Username: username, Password: password}
		str = fmt.Sprintf("{\"dsCredentials\":{\"tenantName\": \"%s\", \"password\": \"%s\", \"userName\": \"%s\"}}", dsm.Tenant, password, username)
		authResponse, err := dsm.SoapClient.AuthenticateTenant(&tenantAuth)
		if err != nil {
			return "", err
		}else{
			return authResponse.AuthenticateTenantReturn, nil
		}
	} else {
		str = fmt.Sprintf("{\"dsCredentials\":{\"password\": \"%s\", \"userName\": \"%s\"}}", password, username)
		url := fmt.Sprintf("%sauthentication/login", dsm.RestURL)
		res, err := grequests.Post(url, &grequests.RequestOptions{HTTPClient: &dsm.RestClient, JSON: []byte(str), IsAjax: false})
		if err != nil {
			return "", err
		}else{
			return res.String(), nil
		}
	}

}

// EndSession logs out of the session with the DSM
func (dsm DSM) EndSession() {
	url := fmt.Sprintf("%sauthentication/logout", dsm.RestURL)
	_, err := grequests.Delete(url, &grequests.RequestOptions{HTTPClient: &dsm.RestClient, Params: map[string]string{"sID": dsm.SessionID}})

	if err != nil {
		log.Println("Unable to make request", err)
	}

}






func (dsm DSM)HostRetrieveByName(hostName string) *gowsdlservice.HostTransport{

	hrbn := gowsdlservice.HostRetrieveByName{Hostname: hostName, SID:dsm.SessionID}
	resp, err := dsm.SoapClient.HostRetrieveByName(&hrbn)
	if err != nil{
		log.Println("Error retrieving host:", err)
	}

	hostTransPort := resp.HostRetrieveByNameReturn
	return hostTransPort
}

//onlyUnassigned is really bool which is not working so pass string true or false
func (dsm DSM) HostRecommendationRuleIDsRetrieve(hostID int, ruleType int, onlyUnassigned string) ([]int32, error){

	hrrir := gowsdlservice.HostRecommendationRuleIDsRetrieve{ HostID:int32(hostID), Type_: int32(ruleType), Onlyunassigned: onlyUnassigned, SID:dsm.SessionID}
	resp, err := dsm.SoapClient.HostRecommendationRuleIDsRetrieve(&hrrir)
	if err != nil{
		log.Println("Error retrieving host:", err)
	}

	if resp == nil {
		err = errors.New(fmt.Sprintf("Error retrieving host with id %d:", hostID))
		return nil, err
	}else {
		return resp.HostRecommendationRuleIDsRetrieveReturn, err
	}

}


func (dsm DSM) HostDetailRetrieve(hostID int, hostGroup int, securityProfileID int, hostType string, hostDetailLevel string) *gowsdlservice.HostDetailTransport{
	if hostDetailLevel == "" {
		hostDetailLevel = "HIGH"
	}

	var hdl gowsdlservice.EnumHostDetailLevel = ""

	if hostDetailLevel == "HIGH"{
		hdl = gowsdlservice.EnumHostDetailLevelHIGH
	}else if hostDetailLevel == "MEDIUM" {
		hdl = gowsdlservice.EnumHostDetailLevelMEDIUM
	}else{
		hdl = gowsdlservice.EnumHostDetailLevelLOW
	}

	var hostType2 string  = "SPECIFIC_HOST"

	hft := gowsdlservice.HostFilterTransport{HostGroupID: int32(hostGroup), HostID: int32(hostID), SecurityProfileID: int32(securityProfileID), Type_: hostType2, }
	hdr := gowsdlservice.HostDetailRetrieve{HostFilter:&hft, HostDetailLevel:&hdl, SID: dsm.SessionID,}
	resp, err := dsm.SoapClient.HostDetailRetrieve(&hdr)
	if err != nil{
		log.Println("Error retrieving host:", err)
	}

	return resp.HostDetailRetrieveReturn[0]

}


//does not currently implement custom time ranges
//timeType "LAST_HOUR", eventOperator="GREATER_THAN", eventID=1
func (dsm DSM)SystemEventRetrieve(timeType string, hostID int, hostGroupID int, securityProfileId int, hostType string, eventID int,
	                              includeNonHostEvents bool, eventOperator string) []*gowsdlservice.SystemEventTransport{


	 tft := gowsdlservice.TimeFilterTransport{RangeFrom: "", RangeTo: "", SpecificTime: "", Type_: timeType}
	 hft := gowsdlservice.HostFilterTransport{HostGroupID: int32(hostGroupID), HostID: int32(hostID), SecurityProfileID: int32(securityProfileId), Type_: hostType}
	 idf := gowsdlservice.IDFilterTransport{Id: int32(eventID), Operator: eventOperator}
	 ser := gowsdlservice.SystemEventRetrieve{TimeFilter:&tft, HostFilter: &hft, EventIdFilter: &idf, IncludeNonHostEvents: includeNonHostEvents, SID: dsm.SessionID}
	 resp, err := dsm.SoapClient.SystemEventRetrieve(&ser)
	if err != nil{
		log.Println("Error retrieving system event:", err)
	}

	return resp.SystemEventRetrieveReturn.SystemEvents.Item
}


func (dsm DSM)DPIRuleRetrieve(ruleID int) (*gowsdlservice.DPIRuleTransport, error){
	dpiRuleRetrieve := gowsdlservice.DPIRuleRetrieve{Id:int32(ruleID), SID: dsm.SessionID}
	resp, err := dsm.SoapClient.DPIRuleRetrieve(&dpiRuleRetrieve)
	if err != nil{
		log.Println("Error could not retrieve dpi rule:", err)
	}


	if resp == nil {
		err = errors.New(fmt.Sprintf("Error retrieving rule with id %d:", ruleID))
		return nil, err
	}else {
		return resp.DPIRuleRetrieveReturn, err
	}
}





func (dsm DSM)HostMoveToHostGroup(hostIDs []int32, hostGroupID int32) *gowsdlservice.HostMoveToHostGroupResponse{
	hmtg := gowsdlservice.HostMoveToHostGroup{HostIDs:hostIDs, HostGroupID: hostGroupID, SID: dsm.SessionID}
	resp, err := dsm.SoapClient.HostMoveToHostGroup(&hmtg)

	if err != nil{
		log.Println("Error moving hosts to group. None moved as:", err)
	}

	return resp
}


func (dsm DSM) HostGroupCreate(name string, external bool, externalID string, parentGroupId int32) (*gowsdlservice.HostGroupTransport, error){
	hgt := gowsdlservice.HostGroupTransport{Name:name, External: external, ExternalID: externalID}
	if parentGroupId != -1{
		hgt.ParentGroupID = parentGroupId
	}
	hgc := gowsdlservice.HostGroupCreate{HostGroup:&hgt, SID: dsm.SessionID}
	resp, err := dsm.SoapClient.HostGroupCreate(&hgc)
	if err != nil{
		log.Println("Error creating host group:", err)
		return nil, err
	}else{
		return resp.HostGroupCreateReturn, nil
	}


}

// HostRetrieveAll retrieves all hosts from the DSM
// returns empty slice if none found or error occurs
func (dsm DSM) HostRetrieveAll() ([]*gowsdlservice.HostTransport, error){
	hra := gowsdlservice.HostRetrieveAll{SID:dsm.SessionID}
	resp, err := dsm.SoapClient.HostRetrieveAll(&hra)
	if err != nil{
		return make([]*gowsdlservice.HostTransport, 0), errors.New("Unable to retrieve all hosts.")
	}else{
		return resp.HostRetrieveAllReturn, nil
	}
}

// HostRetrieveByHostGroup retrieves all hosts in a dsm group by id.
// returns empty slice if none found or error occurs
func (dsm DSM) HostRetrieveByHostGroup(hostGroupId int) ([]*gowsdlservice.HostTransport, error){
	hrgh := gowsdlservice.HostRetrieveByHostGroup{HostGroupID:int32(hostGroupId), SID:dsm.SessionID}
	resp, err  := dsm.SoapClient.HostRetrieveByHostGroup(&hrgh)
	if err != nil{
		return make([]*gowsdlservice.HostTransport, 0), errors.New("Host Group was not found.")
	}else{
		return resp.HostRetrieveByHostGroupReturn, nil
	}
}

// HostGroupRetrieveAll retreives all hostgroups
// returns empty list if error or none found
func (dsm DSM)HostGroupRetrieveAll() ([]*gowsdlservice.HostGroupRetrieveAllReturnTransport, error){
	hgra := gowsdlservice.HostGroupRetrieveAll{SID: dsm.SessionID}
	resp, err := dsm.SoapClient.HostGroupRetrieveAll(&hgra)
	if err != nil{
		return make([]*gowsdlservice.HostGroupRetrieveAllReturnTransport, 0), errors.New("Could not retreive host groups.")
	}else{
		return resp.HostGroupRetrieveAllReturn, nil
	}
}

// HostClearWarningsErrors clears warning and errors on a single host of list of hosts
// in all cases it returns an empty HostClearWarningsErrorsResponse object. note* I have yet to find error condition.
func (dsm DSM)HostClearWarningsErrors(hosts []int32) *gowsdlservice.HostClearWarningsErrorsResponse{
	hce := gowsdlservice.HostClearWarningsErrors{HostIDs:hosts, SID:dsm.SessionID,}
	response, _ := dsm.SoapClient.HostClearWarningsErrors(&hce)
	return response
}

// HostGetStatus retrieves a host status transport for a host by id
// returns nil for HostStatusTransport if error found
func (dsm DSM) HostGetStatus(host int32) (*gowsdlservice.HostStatusTransport, error) {
	hgs := gowsdlservice.HostGetStatus{Id: host, SID: dsm.SessionID,}
	response, err := dsm.SoapClient.HostGetStatus(&hgs)

	if err != nil {
		return nil, errors.New(fmt.Sprintf("Unable to get host status for host: %d", host))
	}else{
		return response.HostGetStatusReturn, nil
	}
}

// HostRecommendationScan initiates a host recommendation scan for an individual or list of hosts
// returns nil if no error found
func (dsm DSM) HostRecommendationScan(hosts []int32) error{
	hrs := gowsdlservice.HostRecommendationScan{HostIDs: hosts, SID: dsm.SessionID}
	_, err := dsm.SoapClient.HostRecommendationScan(&hrs)
	if err != nil{
		return errors.New(fmt.Sprintf("Error intiating host reccomentdation scan on hosts %d", hosts))
	}else{
		return nil
	}

}
