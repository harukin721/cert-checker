package cmd

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var okCount, ngCount int

var certCheckerCmd = &cobra.Command{
	Use:   "certChecker",
	Short: "A CLI tool to check SSL certificate expiration",
	Long:  `ssl_checker is a CLI tool that checks the expiration date of SSL certificates for a given list of URLs.`,

	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		file, err := os.Open(args[0])
		if err != nil {
			log.Fatalf("Failed to open file: %s", err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			url := scanner.Text()
			expirationDate, err := getExpirationDate(url)
			if err != nil {
				log.Printf("Error checking SSL certificate expiration for %s: %s", url, err)
				ngCount++
				continue
			}

			log.Printf("SSL certificate for %s expires on: %s", url, expirationDate.Format("2006-01-02"))
			if time.Now().After(expirationDate) {
				ngCount++
			} else {
				okCount++
			}
		}

		if err := scanner.Err(); err != nil {
			log.Fatalf("Failed to read file: %s", err)
		}

		fmt.Println()
		log.Printf("OK: %d, NG: %d", okCount, ngCount)
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
