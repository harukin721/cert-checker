package cmd

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"os"
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
	conn, err := tls.Dial("tcp", net.JoinHostPort(url, "443"), nil)
	if err != nil {
		return time.Time{}, err
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return time.Time{}, fmt.Errorf("no certificates found for URL: %s", url)
	}

	return certs[0].NotAfter, nil
}

func init() {
	rootCmd.AddCommand(certCheckerCmd)
}
