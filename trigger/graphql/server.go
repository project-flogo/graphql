package graphql

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/project-flogo/core/data/coerce"
	logger "github.com/project-flogo/core/support/log"
)

// Graceful shutdown HttpServer from: https://github.com/corneldamian/httpway/blob/master/server.go

// NewServer create a new server instance
// param server - is a instance of http.Server, can be nil and a default one will be created
func NewServer(addr string, handler http.Handler) *Server {
	srv := &Server{}
	srv.Server = &http.Server{Addr: addr, Handler: handler}

	return srv
}

// Server the server  structure
type Server struct {
	*http.Server

	serverInstanceID         string
	listener                 net.Listener
	lastError                error
	serverGroup              *sync.WaitGroup
	clientsGroup             chan bool
	secureConnection         bool
	serverKey, caCertificate string
}

// InstanceID the server instance id
func (s *Server) InstanceID() string {
	return s.serverInstanceID
}

// Start this will start server
// command isn't blocking, will exit after run
func (s *Server) Start() error {
	if s.Handler == nil {
		return errors.New("No server handler set")
	}

	if s.listener != nil {
		return errors.New("Server already started")
	}

	addr := s.Addr
	if addr == "" {
		addr = ":http"
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	if s.secureConnection {
		logger.RootLogger().Debug("Reading certificates")
		privateKey, err := s.decodeCertificate(s.serverKey)
		if err != nil {
			return err
		}
		CACertificate, err := s.decodeCertificate(s.caCertificate)
		if err != nil {
			return err
		}
		tlsConfig := &tls.Config{}
		finalCert, err := tls.X509KeyPair(CACertificate, privateKey)
		if err != nil {
			return err
		}
		tlsConfig.Certificates = []tls.Certificate{finalCert}
		listener = tls.NewListener(listener, tlsConfig)
	}

	hostname, _ := os.Hostname()
	s.serverInstanceID = fmt.Sprintf("%x", md5.Sum([]byte(hostname+addr)))

	s.listener = listener
	s.serverGroup = &sync.WaitGroup{}
	s.clientsGroup = make(chan bool, 50000)

	//if s.ErrorLog == nil {
	//    if r, ok := s.Handler.(ishttpwayrouter); ok {
	//        s.ErrorLog = log.New(&internalServerLoggerWriter{r.(*Router).Logger}, "", 0)
	//    }
	//}
	//
	s.Handler = &serverHandler{s.Handler, s.clientsGroup, s.serverInstanceID}

	s.serverGroup.Add(1)
	go func() {
		defer s.serverGroup.Done()

		err := s.Serve(listener)
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}

			s.lastError = err
		}
	}()

	return nil
}

// Stop sends stop command to the server
func (s *Server) Stop() error {
	if s.listener == nil {
		return errors.New("Server not started")
	}

	if err := s.listener.Close(); err != nil {
		return err
	}

	return s.lastError
}

// IsStarted checks if the server is started
// will return true even if the server is stopped but there are still some requests to finish
func (s *Server) IsStarted() bool {
	if s.listener != nil {
		return true
	}

	if len(s.clientsGroup) > 0 {
		return true
	}

	return false
}

// WaitStop waits until server is stopped and all requests are finish
// timeout - is the time to wait for the requests to finish after the server is stopped
// will return error if there are still some requests not finished
func (s *Server) WaitStop(timeout time.Duration) error {
	if s.listener == nil {
		return errors.New("Server not started")
	}

	s.serverGroup.Wait()

	checkClients := time.Tick(100 * time.Millisecond)
	timeoutTime := time.NewTimer(timeout)

	for {
		select {
		case <-checkClients:
			if len(s.clientsGroup) == 0 {
				return s.lastError
			}
		case <-timeoutTime.C:
			return fmt.Errorf("WaitStop error, timeout after %s waiting for %d client(s) to finish", timeout, len(s.clientsGroup))
		}
	}
}

func (s *Server) decodeCertificate(cert string) ([]byte, error) {
	if cert == "" {
		return nil, fmt.Errorf("Certificate is Empty")
	}

	// case 1: if certificate comes from fileselctor it will be base64 encoded
	if strings.HasPrefix(cert, "{") {
		logger.RootLogger().Debug("Certificate received from file selector")
		certObj, err := coerce.ToObject(cert)
		if err == nil {
			certValue, ok := certObj["content"].(string)
			if !ok || certValue == "" {
				return nil, fmt.Errorf("No content found for certificate")
			}
			return base64.StdEncoding.DecodeString(strings.Split(certValue, ",")[1])
		}
		return nil, err
	}

	// case 2: if the certificate is defined as application property in the format "<encoding>,<encodedCertificateValue>"
	index := strings.IndexAny(cert, ",")
	if index > -1 {
		//some encoding is there
		logger.RootLogger().Debug("Certificate received from application property with encoding")
		encoding := cert[:index]
		certValue := cert[index+1:]

		if strings.EqualFold(encoding, "base64") {
			return base64.StdEncoding.DecodeString(certValue)
		}
		return nil, fmt.Errorf("Error parsing the certificate or given encoding may not be supported")
	}

	// case 3: if the certificate is defined as application property that points to a file
	if strings.HasPrefix(cert, "file://") {
		// app property pointing to a file
		logger.RootLogger().Debug("Certificate received from application property pointing to a file")
		fileName := cert[7:]
		return ioutil.ReadFile(fileName)
	}

	// case 4: if certificate is defined as path to a file (in oss)
	if strings.Contains(cert, "/") || strings.Contains(cert, "\\") {
		logger.RootLogger().Debug("Certificate received from settings as file path")
		_, err := os.Stat(cert)
		if err != nil {
			logger.RootLogger().Errorf("Cannot find certificate file: %s", err.Error())
		}
		return ioutil.ReadFile(cert)
	}

	// case 5: Attempt to decode as base64
	decode, err := base64.StdEncoding.DecodeString(cert)
	if err == nil {
		logger.RootLogger().Debug("Certificate received as base64 encoded string")
		return decode, nil
	}

	logger.RootLogger().Debug("Certificate received from application property without encoding")
	return []byte(cert), nil
}

type serverHandler struct {
	handler          http.Handler
	clientsGroup     chan bool
	serverInstanceID string
}

func (sh *serverHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sh.clientsGroup <- true
	defer func() {
		<-sh.clientsGroup
	}()

	w.Header().Add("X-Server-Instance-Id", sh.serverInstanceID)

	sh.handler.ServeHTTP(w, r)
}
