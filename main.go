package main

import (
	"context"
	"fmt"
	"os"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

func main() {
	if len(os.Args) != 5 {
		fmt.Println("Usage: go run main.go <compartment_ocid> <subnet_to_find> <subnet_to_add> <rule_description>")
		os.Exit(1)
	}

	compartmentOCID := os.Args[1]
	subnetToFind := os.Args[2]
	subnetToAdd := os.Args[3]
	ruleDescription := os.Args[4]

	configProvider := common.DefaultConfigProvider()
	client, err := core.NewVirtualNetworkClientWithConfigurationProvider(configProvider)
	if err != nil {
		fmt.Printf("Error creating VirtualNetworkClient: %v\n", err)
		return
	}

	ctx := context.Background()

	// Get a list of all route tables
	listRouteTablesRequest := core.ListRouteTablesRequest{
		CompartmentId: common.String(compartmentOCID),
	}
	listRouteTablesResponse, err := client.ListRouteTables(ctx, listRouteTablesRequest)
	if err != nil {
		fmt.Printf("Error listing route tables: %v\n", err)
		return
	}

	for _, routeTable := range listRouteTablesResponse.Items {
		updateRouteTable := false
		var targetDrg *string

		for _, route := range routeTable.RouteRules {
			if *route.Destination == subnetToFind {
				updateRouteTable = true
				targetDrg = route.NetworkEntityId
				break
			}
		}

		if updateRouteTable {
			found := false
			for _, route := range routeTable.RouteRules {
				if *route.Destination == subnetToAdd {
					found = true
					break
				}
			}

			if !found {
				updateRouteTableDetails := core.UpdateRouteTableDetails{
					RouteRules: []core.RouteRule{
						{
							Destination:     common.String(subnetToAdd),
							NetworkEntityId: targetDrg,
							Description:     common.String(ruleDescription),
						},
					},
				}
				updateRouteTableRequest := core.UpdateRouteTableRequest{
					RtId:                    routeTable.Id,
					UpdateRouteTableDetails: updateRouteTableDetails,
				}
				_, err := client.UpdateRouteTable(ctx, updateRouteTableRequest)
				if err != nil {
					fmt.Printf("Error updating route table %s: %v\n", *routeTable.Id, err)
				} else {
					fmt.Printf("Updated route table %s\n", *routeTable.Id)
				}
			}
		}
	}

	// Get a list of all security lists
	listSecurityListsRequest := core.ListSecurityListsRequest{
		CompartmentId: common.String(compartmentOCID),
	}
	listSecurityListsResponse, err := client.ListSecurityLists(ctx, listSecurityListsRequest)
	if err != nil {
		fmt.Printf("Error listing security lists: %v\n", err)
		return
	}

	for _, securityList := range listSecurityListsResponse.Items {
		updateSecurityList := false

		for _, ingressRule := range securityList.IngressSecurityRules {
			if ingressRule.Source == common.String(subnetToFind) {
				updateSecurityList = true
				break
			}
		}

		if updateSecurityList {
			found := false
			for _, ingressRule := range securityList.IngressSecurityRules {
				if ingressRule.Source == common.String(subnetToAdd) {
					found = true
					break
				}
			}

			if !found {
				updateSecurityListDetails := core.UpdateSecurityListDetails{
					IngressSecurityRules: append(securityList.IngressSecurityRules, core.IngressSecurityRule{
						Source:      common.String(subnetToAdd),
						Description: common.String(ruleDescription),
					}),
				}
				updateSecurityListRequest := core.UpdateSecurityListRequest{
					SecurityListId:            securityList.Id,
					UpdateSecurityListDetails: updateSecurityListDetails,
				}
				_, err := client.UpdateSecurityList(ctx, updateSecurityListRequest)
				if err != nil {
					fmt.Printf("Error updating security list %s: %v\n", *securityList.Id, err)
				} else {
					fmt.Printf("Updated security list %s\n", *securityList.Id)
				}
			}
		}
	}
}
