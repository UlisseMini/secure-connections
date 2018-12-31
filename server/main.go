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
	server := getServer("../ca/minica.pem")
	http.HandleFunc("/", indexHandler)
	must(server.ListenAndServeTLS("", ""))
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Handling request")
	w.Write([]byte("Hey GopherCon!"))
}

func getServer(pemFile string) (*http.Server, error) {
	cp := x509.NewCertPool()
	data, err := ioutil.ReadFile(pemFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read %q: %v", pemFile, err)
	}

	cp.AppendCertsFromPEM(data)

	// c, _ := tls.LoadX509KeyPair("cert.pem", "key.pem")

	tlsconf := &tls.Config{
		// Certificates:          []tls.Certificate{c},
		ClientCAs:             cp,
		ClientAuth:            tls.RequireAndVerifyClientCert,
		GetCertificate:        utils.CertReqFunc("cert.pem", "key.pem"),
		VerifyPeerCertificate: utils.CertificateChains,
	}

	server := &http.Server{
		Addr:      ":8080",
		TLSConfig: tlsconf,
	}
	return server
}

func must(err error) {
	if err != nil {
		fmt.Printf("Server error: %v\n", err)
		os.Exit(1)
	}
}

// cert := "cert"
// fmt.Println("My certificate:")
// must(utils.OutputPEMFile(cert))
// c, _ = tls.LoadX509KeyPair(cert, "key")

// fmt.Println("Certificate authority:")
// must(utils.OutputPEMFile("../ca/cert"))
// cp, _ := x509.SystemCertPool()
// data, _ := ioutil.ReadFile("../ca/cert")
// cp.AppendCertsFromPEM(data)

// NoClientCert ClientAuthType = iota
// RequestClientCert
// RequireAnyClientCert
// VerifyClientCertIfGiven
// RequireAndVerifyClientCert

// RootCAs:               cp,
// ClientCAs:             cp,
// VerifyPeerCertificate: utils.CertificateChains,
// GetCertificate:        getCert,
// GetClientCertificate:  getClientCert,
