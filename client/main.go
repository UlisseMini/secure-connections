package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/lizrice/secure-connections/utils"
)

func main() {
	client := getClient()
	resp, err := client.Get("https://127.0.0.1:8080")
	mustNot(err)

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	mustNot(err)

	fmt.Printf("Status: %s  Body: %s\n", resp.Status, string(body))
}

func getClient(cert, key string) *http.Client {
	cp := x509.NewCertPool()
	data, _ := ioutil.ReadFile("../ca/minica.pem")
	cp.AppendCertsFromPEM(data)

	// If you want to load a client cert
	// c, err := tls.LoadX509KeyPair("signed-cert", "key")

	config := &tls.Config{
		// Certificates's is only used when the server is doing client
		// authentication, normally not because webservers want anyone to
		// be able to use them
		// Certificates: []tls.Certificate{c},

		// RootCA's are the trusted certificate authories for the client
		RootCAs: cp,

		// GetClientCertificate allows you to use a custom function
		// for getting the client certificate (see above)
		GetClientCertificate: utils.ClientCertReqFunc("cert.pem", "key.pem"),

		// Create a custom function for verifying the peers certificate.
		// you should avoid this it has been done here for the talk
		VerifyPeerCertificate: utils.CertificateChains,
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
}

func mustNot(err error) {
	if err != nil {
		fmt.Printf("Client error: %v\n", err)
		os.Exit(1)
	}
}

// fmt.Println("Certificate authority:")
// mustNot(utils.OutputPEMFile("../ca/cert"))
// cp, _ := x509.SystemCertPool() or
// cp := x509.NewCertPool()
// data, _ := ioutil.ReadFile("../ca/cert")
// cp.AppendCertsFromPEM(data)

// fmt.Println("My certificate:")
// mustNot(utils.OutputPEMFile("signed-cert"))
// c, _ := tls.LoadX509KeyPair("signed-cert", "key")

// InsecureSkipVerify: true,
// RootCAs:               cp,
// Certificates:          []tls.Certificate{c},
