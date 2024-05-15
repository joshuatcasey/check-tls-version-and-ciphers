package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"os"
)

func main() {
	if len(os.Args) < 3 {
		log.Fatalf("Usage: %s <host> <port>\n", os.Args[0])
	}

	host := os.Args[1]
	port := os.Args[2]

	fmt.Printf("Using host %q and port %q\n", host, port)

	supportedTLSVersions := determineServerSupportedTLSVersions(host, port)
	supportedTLSCiphers := determineServerSupportedCipherSuitesForTLSOneDotTwo(host, port)

	fmt.Printf("Supported TLS Versions:\n")
	for _, tlsVersion := range supportedTLSVersions {
		fmt.Printf("- %s\n", tls.VersionName(tlsVersion))
	}
	fmt.Printf("Supported TLS1.2 Ciphers:\n")
	for _, tlsVersion := range supportedTLSCiphers {
		fmt.Printf("- %s\n", tls.CipherSuiteName(tlsVersion))
	}
}

func doesServerSupportCipherForTLSOneDotTwo(cipher uint16, host, port string) (bool, error) {
	config := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			cipher,
		},
		InsecureSkipVerify: true, //just for testing
	}
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%s", host, port), config)
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()
	if err != nil {
		if err.Error() == "remote error: tls: handshake failure" {
			return false, nil
		}
		// return other errors, such as DNS errors and lookup errors
		return false, err
	}

	if cipher == conn.ConnectionState().CipherSuite {
		return true, nil
	}
	return false, fmt.Errorf("client negotiated unexpected cipher suite %s, expected cipher suite %s",
		tls.CipherSuiteName(conn.ConnectionState().CipherSuite),
		tls.CipherSuiteName(cipher))
}

func determineServerSupportedCipherSuitesForTLSOneDotTwo(host, port string) []uint16 {
	var allCiphers []uint16
	for _, suite := range tls.CipherSuites() {
		allCiphers = append(allCiphers, suite.ID)
	}
	for _, suite := range tls.InsecureCipherSuites() {
		allCiphers = append(allCiphers, suite.ID)
	}

	var serverSupportedCiphers []uint16
	for _, cipher := range allCiphers {
		supported, err := doesServerSupportCipherForTLSOneDotTwo(cipher, host, port)
		if err != nil {
			fmt.Printf("error checking if server supports cipher suites %q: %s\n",
				tls.CipherSuiteName(cipher),
				err.Error())
		}
		if supported {
			serverSupportedCiphers = append(serverSupportedCiphers, cipher)
		}
	}
	return serverSupportedCiphers
}

func doesServerSupportTLSVersion(tlsVersion uint16, host, port string) (bool, error) {
	config := &tls.Config{
		MinVersion:         tlsVersion,
		MaxVersion:         tlsVersion,
		InsecureSkipVerify: true, //just for testing
	}
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%s", host, port), config)
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()
	if err != nil {
		if err.Error() == "tls: no supported versions satisfy MinVersion and MaxVersion" {
			return false, nil
		}
		if err.Error() == "remote error: tls: protocol version not supported" {
			return false, nil
		}
		// return other errors, such as DNS errors and lookup errors
		return false, err
	}

	if conn.ConnectionState().Version == tlsVersion {
		return true, nil
	}
	return false, fmt.Errorf("client negotiated unexpected TLS Version %q, expected TLS Version %q\n",
		tls.VersionName(conn.ConnectionState().Version),
		tls.VersionName(tlsVersion))
}

func determineServerSupportedTLSVersions(host, port string) []uint16 {
	allTLSVersions := []uint16{
		tls.VersionTLS10,
		tls.VersionTLS11,
		tls.VersionTLS12,
		tls.VersionTLS13,
	}

	var serverSupportedTLSVersions []uint16
	for _, tlsVersion := range allTLSVersions {
		supported, err := doesServerSupportTLSVersion(tlsVersion, host, port)
		if err != nil {
			fmt.Printf("error checking if server supports TLS version %q: %s\n",
				tls.VersionName(tlsVersion),
				err.Error())
		}
		if supported {
			serverSupportedTLSVersions = append(serverSupportedTLSVersions, tlsVersion)
		}
	}
	return serverSupportedTLSVersions
}
