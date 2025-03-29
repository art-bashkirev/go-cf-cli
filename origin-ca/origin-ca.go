package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/cloudflare/cloudflare-go/v4"
	"github.com/cloudflare/cloudflare-go/v4/origin_ca_certificates"
	"github.com/cloudflare/cloudflare-go/v4/shared"
	"github.com/cloudflare/cloudflare-go/v4/ssl"
)

func main() {
	// Initialize Cloudflare client
	client := cloudflare.NewClient()

	// Get user input for hostnames, request type, and validity
	var hostnames []string
	var requestType string
	var validity int

	fmt.Println("Enter hostnames (comma separated):")
	var input string
	fmt.Scanln(&input)
	hostnames = splitAndTrim(input)

	fmt.Println("Enter request type (origin-rsa/origin-ecc/keyless-certificate):")
	fmt.Scanln(&requestType)

	fmt.Println("Enter validity in days:")
	fmt.Scanln(&validity)

	// Read the CSR from a file
	csrFilePath := "./csr.txt"
	csrFile, err := os.ReadFile(csrFilePath)
	if err != nil {
		log.Fatalf("Error reading CSR file: %v", err)
	}
	csr := string(csrFile)

	// Create the Origin CA certificate
	params := origin_ca_certificates.OriginCACertificateNewParams{
		Csr:               cloudflare.F(csr),
		Hostnames:         cloudflare.F(hostnames),
		RequestType:       cloudflare.F(shared.CertificateRequestType(requestType)),
		RequestedValidity: cloudflare.F(ssl.RequestValidity(validity)),
	}

	originCACertificate, err := client.OriginCACertificates.New(context.TODO(), params)
	if err != nil {
		log.Fatalf("Error creating Origin CA certificate: %v", err)
	}

	// Output the result
	fmt.Printf("Hostnames: %v\n", originCACertificate.Hostnames)
	fmt.Printf("Requested Validity: %d days\n", int(originCACertificate.RequestedValidity))
	fmt.Printf("Expires On: %s\n", originCACertificate.ExpiresOn)
}

// Helper function to split and trim hostnames
func splitAndTrim(input string) []string {
	var result []string
	for _, hostname := range strings.Split(input, ",") {
		result = append(result, strings.TrimSpace(hostname))
	}
	return result
}
