package cmd

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var certCheckerCmd = &cobra.Command{
	Use:   "certChecker",
	Short: "A CLI tool to check SSL certificate expiration",
	Long:  `ssl_checker is a CLI tool that checks the expiration date of SSL certificates for a given list of URLs.`,

	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 1 {
			fmt.Println("Usage: certChecker <file>")
			return
		}
		filePath := args[0]
		file, err := os.Open(filePath)
		if err != nil {
			fmt.Printf("Error opening file: %v\n", err)
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			url := scanner.Text()
			expirationDate, err := getExpirationDate(url)
			if err != nil {
				fmt.Printf("Error checking SSL certificate expiration for %s: %v\n", url, err)
				continue
			}
			fmt.Printf("SSL certificate for %s expires on: %s\n", url, expirationDate.Format("2006-01-02"))
		}

		if err := scanner.Err(); err != nil {
			fmt.Printf("Error reading file: %v\n", err)
		}
	},
}

func getExpirationDate(url string) (time.Time, error) {
	cmd := exec.Command("openssl", "s_client", "-connect", url+":443", "-servername", url, "-showcerts")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return time.Time{}, err
	}

	certInfo := out.String()
	certStart := strings.Index(certInfo, "-----BEGIN CERTIFICATE-----")
	certEnd := strings.Index(certInfo, "-----END CERTIFICATE-----")
	if certStart == -1 || certEnd == -1 {
		return time.Time{}, fmt.Errorf("certificate not found in output")
	}
	certPEM := certInfo[certStart : certEnd+len("-----END CERTIFICATE-----")]

	// Parse certificate PEM and extract expiration date
	cert, err := parseCertificatePEM(certPEM)
	if err != nil {
		return time.Time{}, err
	}

	return cert.NotAfter, nil
}

func parseCertificatePEM(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func init() {
	rootCmd.AddCommand(certCheckerCmd)
}
