package graphql

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/TIBCOSoftware/flogo-lib/core/data"
	"github.com/TIBCOSoftware/flogo-lib/logger"
)

// Graceful shutdown HttpServer from: https://github.com/corneldamian/httpway/blob/master/server.go

// NewServer create a new server instance
//param server - is a instance of http.Server, can be nil and a default one will be created
func NewServer(addr string, handler http.Handler) *Server {
	srv := &Server{}
	srv.Server = &http.Server{Addr: addr, Handler: handler}

	return srv
}

//Server the server  structure
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
		logger.Debug("Reading certificates")
		privateKey, err := decodeCerts(s.serverKey)
		if err != nil {
			return err
		}
		CACertificate, err := decodeCerts(s.caCertificate)
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

func decodeCerts(certVal string) ([]byte, error) {
	if certVal == "" {
		return nil, fmt.Errorf("Certificate is Empty")
	}

	//if certificate comes from fileselctor it will be base64 encoded
	if strings.HasPrefix(certVal, "{") {
		logger.Debug("Certificate received from FileSelector")
		certObj, err := data.CoerceToObject(certVal)
		if err == nil {
			certRealValue, ok := certObj["content"].(string)
			logger.Debug("Fetched Content from Certificate Object")
			if !ok || certRealValue == "" {
				return nil, fmt.Errorf("Didn't found the certificate content")
			}

			index := strings.IndexAny(certRealValue, ",")
			if index > -1 {
				certRealValue = certRealValue[index+1:]
			}

			return base64.StdEncoding.DecodeString(certRealValue)
		}
		return nil, err
	}

	//if the certificate comes from application properties need to check whether that it contains , ans encoding
	index := strings.IndexAny(certVal, ",")

	if index > -1 {
		//some encoding is there
		logger.Debug("Certificate received from App properties with encoding")
		encoding := certVal[:index]
		certRealValue := certVal[index+1:]

		if strings.EqualFold(encoding, "base64") {
			return base64.StdEncoding.DecodeString(certRealValue)
		}
		return nil, fmt.Errorf("Error in parsing the certificates Or we may be not be supporting the given encoding")
	}

	logger.Debug("Certificate received from App properties without encoding")

	//===========These blocks of code to be removed after FLOGO-2673 is resolved =================================
	first := strings.TrimSpace(certVal[:strings.Index(certVal, "----- ")] + "-----")
	middle := strings.TrimSpace(certVal[strings.Index(certVal, "----- ")+5 : strings.Index(certVal, " -----")])
	strings.Replace(middle, " ", "\n", -1)
	last := strings.TrimSpace(certVal[strings.Index(certVal, " -----"):])
	certVal = first + "\n" + middle + "\n" + last
	//===========These blocks of code to be removed after FLOGO-2673 is resolved =================================

	return []byte(certVal), nil
}
