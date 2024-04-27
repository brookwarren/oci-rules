package main

import (
	"context"
	"fmt"
	"os"
	"reflect"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

func main() {
	if len(os.Args) != 5 {
		fmt.Println("Usage: go run main.go <compartment_ocid> <CIDR_to_find> <CIDR_to_add> <rule_description>")
		os.Exit(1)
	}

	compartmentOCID := os.Args[1]
	CidrToFind := os.Args[2]
	CidrToAdd := os.Args[3]
	//	ruleDescription := os.Args[4]

	fmt.Println(compartmentOCID)
	fmt.Println(CidrToFind)
	fmt.Println(CidrToAdd)
	//	fmt.Println(ruleDescription)

	configProvider := common.DefaultConfigProvider()
	client, err := core.NewVirtualNetworkClientWithConfigurationProvider(configProvider)
	if err != nil {
		fmt.Printf("Error creating VirtualNetworkClient: %v\n", err)
		return
	}

	identityClient, err := identity.NewIdentityClientWithConfigurationProvider(configProvider)
	if err != nil {
		fmt.Printf("Error creating IdentityClient: %v\n", err)
		return
	}

	ctx := context.Background()

	// Recursively process each compartment and its sub-compartments
	processCompartment(ctx, client, identityClient, compartmentOCID, CidrToFind, CidrToAdd)
}

func processCompartment(ctx context.Context, client core.VirtualNetworkClient, identityClient identity.IdentityClient, compartmentID, CidrToFind, CidrToAdd string) {
	// Process route tables and security lists for the current compartment
	processRouteTables(ctx, client, compartmentID, CidrToFind, CidrToAdd)
	processSecurityLists(ctx, client, compartmentID, CidrToFind, CidrToAdd)

	// Retrieve the list of sub-compartments
	listCompartmentsRequest := identity.ListCompartmentsRequest{
		CompartmentId: common.String(compartmentID),
	}
	listCompartmentsResponse, err := identityClient.ListCompartments(ctx, listCompartmentsRequest)
	if err != nil {
		fmt.Printf("Error listing compartments: %v\n", err)
		return
	}

	// Recursively process each sub-compartment
	for _, subCompartment := range listCompartmentsResponse.Items {
		processCompartment(ctx, client, identityClient, *subCompartment.Id, CidrToFind, CidrToAdd)
	}
}

func processRouteTables(ctx context.Context, client core.VirtualNetworkClient, compartmentID, CidrToFind, CidrToAdd string) {
	// Get a list of all route tables
	listRouteTablesRequest := core.ListRouteTablesRequest{
		CompartmentId: common.String(compartmentID),
	}
	listRouteTablesResponse, err := client.ListRouteTables(ctx, listRouteTablesRequest)
	if err != nil {
		fmt.Printf("Error listing route tables: %v\n", err)
		return
	}

	for _, routeTable := range listRouteTablesResponse.Items {
		foundRoutes := []core.RouteRule{}
		for _, route := range routeTable.RouteRules {
			if *route.Destination == CidrToFind {
				foundRoutes = append(foundRoutes, route)
			}
		}

		fmt.Println("foundRoutes:")
		fmt.Println(foundRoutes)

		for i := range foundRoutes {
			foundRoutes[i].Destination = common.String(CidrToAdd)
		}

		fmt.Println("Rewriting CIDR in foundRoutes:")
		fmt.Println(foundRoutes)

		// Check for duplicate routes and remove them from foundRoutes
		for i := len(foundRoutes) - 1; i >= 0; i-- {
			for _, route := range routeTable.RouteRules {
				if *foundRoutes[i].Destination == *route.Destination {
					foundRoutes = append(foundRoutes[:i], foundRoutes[i+1:]...)
					break
				}
			}
		}

		fmt.Println("Removed duplicate routes from foundRoutes:")
		fmt.Println(foundRoutes)

		// Update the route table with the new routes
		if len(foundRoutes) > 0 {
			updateRouteTableRequest := core.UpdateRouteTableRequest{
				RtId: routeTable.Id,
				UpdateRouteTableDetails: core.UpdateRouteTableDetails{
					RouteRules: append(routeTable.RouteRules, foundRoutes...),
				},
			}

			_, err := client.UpdateRouteTable(ctx, updateRouteTableRequest)
			if err != nil {
				fmt.Printf("Error updating route table: %v\n", err)
				continue
			}

			fmt.Printf("Successfully updated route table: %s\n", *routeTable.Id)
		}
	}
}

func processSecurityLists(ctx context.Context, client core.VirtualNetworkClient, compartmentID, CidrToFind, CidrToAdd string) {
	// Get a list of all security lists
	listSecurityListsRequest := core.ListSecurityListsRequest{
		CompartmentId: common.String(compartmentID),
	}

	listSecurityListsResponse, err := client.ListSecurityLists(ctx, listSecurityListsRequest)
	if err != nil {
		fmt.Printf("Error listing security lists: %v\n", err)
		return
	}

	for _, securityList := range listSecurityListsResponse.Items {
		foundRules := []core.IngressSecurityRule{}

		for _, rule := range securityList.IngressSecurityRules {
			if *rule.Source == CidrToFind {
				foundRules = append(foundRules, rule)
			}
		}

		fmt.Println("Found ingress rules:")
		fmt.Println(foundRules)

		for i := range foundRules {
			foundRules[i].Source = common.String(CidrToAdd)
		}

		fmt.Println("Rewriting source CIDRs in found ingress rules:")
		fmt.Println(foundRules)

		// Check for duplicate rules and remove them from foundRules
		for i := len(foundRules) - 1; i >= 0; i-- {
			for _, rule := range securityList.IngressSecurityRules {
				if reflect.DeepEqual(foundRules[i], rule) {
					foundRules = append(foundRules[:i], foundRules[i+1:]...)
					break
				}
			}
		}

		fmt.Println("Removed duplicate ingress rules from foundRules:")
		fmt.Println(foundRules)

		// Update the security list with the new ingress rules
		if len(foundRules) > 0 {
			updateSecurityListRequest := core.UpdateSecurityListRequest{
				SecurityListId: securityList.Id,
				UpdateSecurityListDetails: core.UpdateSecurityListDetails{
					IngressSecurityRules: append(securityList.IngressSecurityRules, foundRules...),
				},
			}

			_, err := client.UpdateSecurityList(ctx, updateSecurityListRequest)
			if err != nil {
				fmt.Printf("Error updating security list: %v\n", err)
				continue
			}

			fmt.Printf("Successfully updated security list: %s\n", *securityList.Id)
		}
	}
}
