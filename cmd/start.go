package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var validTokens = map[string]bool{
	"token123": true,
	"token456": true,
}

type CertRequest struct {
	CommonName   string   `json:"common_name"`
	Organization []string `json:"organization"`
	// Add additional fields as needed
}

// startCmd represents the start command
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		caCertPath := "ca_cert.pem"
		caKeyPath := "ca_key.pem"

		var caCert *x509.Certificate
		var caKey *rsa.PrivateKey

		// Check if CA files exist
		if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
			// Files do not exist, generate new CA certificate and key
			caCert, caKey, err = generateCACertificate()
			if err != nil {
				log.Fatal(err)
			}

			// Save the CA certificate and key to files
			err = saveCACertificateAndKey(caCert, caKey, caCertPath, caKeyPath)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			// Files exist, load the CA certificate and key
			caCert, caKey, err = loadCACertificateAndKey(caCertPath, caKeyPath)
			if err != nil {
				log.Fatal(err)
			}
		}

		http.Handle("/issue", authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req CertRequest
			err := json.NewDecoder(r.Body).Decode(&req)
			if err != nil {
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}

			certPEM, err := issueCertificate(caCert, caKey, req)
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/x-pem-file")
			w.Write(certPEM)
		})))

		log.Println("CA Manager running on :8080")
		log.Fatal(http.ListenAndServe(":8080", nil))
	},
}

func init() {
	rootCmd.AddCommand(startCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// startCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// startCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func generateCACertificate() (*x509.Certificate, *rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	caTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"My CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // Valid for 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, nil, err
	}

	return caCert, privateKey, nil
}

func authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if !validTokens[token] {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func issueCertificate(caCert *x509.Certificate, caKey *rsa.PrivateKey, req CertRequest) ([]byte, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	certTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   req.CommonName,
			Organization: req.Organization,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0), // Valid for 1 year
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	// Generate client private key
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)})

	// Combine certificate and key
	fullPEM := append(certPEM, keyPEM...)

	return fullPEM, nil
}

func saveCACertificateAndKey(caCert *x509.Certificate, caKey *rsa.PrivateKey, certPath string, keyPath string) error {
	// Encode the CA certificate to PEM format
	caCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCert.Raw,
	})

	// Encode the CA private key to PEM format
	caKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caKey),
	})

	// Write the CA certificate to file
	err := os.WriteFile(certPath, caCertPEM, 0600)
	if err != nil {
		return err
	}

	// Write the CA private key to file
	err = os.WriteFile(keyPath, caKeyPEM, 0600)
	if err != nil {
		return err
	}

	return nil
}

func loadCACertificateAndKey(certPath string, keyPath string) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Read the CA certificate file
	caCertPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}

	// Read the CA private key file
	caKeyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}

	// Decode the CA certificate PEM block
	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil || caCertBlock.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("failed to decode CA certificate PEM")
	}

	// Parse the CA certificate
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	// Decode the CA private key PEM block
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil || caKeyBlock.Type != "RSA PRIVATE KEY" {
		return nil, nil, fmt.Errorf("failed to decode CA private key PEM")
	}

	// Parse the CA private key
	caKey, err := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return caCert, caKey, nil
}
