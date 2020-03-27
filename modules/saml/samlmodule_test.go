package saml

import (
	"bytes"
	"net/http"
	"testing"
)

var (
	samlProviderModule *SamlProviderModule
)

func TestSamlProviderModule(t *testing.T) {
}


//Utils
type MockResponseWriter struct {
	statusCode int
	buffer     *bytes.Buffer
	headers    http.Header
}

func (w MockResponseWriter) Header() http.Header {
	return w.headers
}

func (w MockResponseWriter) Write(b []byte) (int, error) {
	if w.buffer != nil {
		return w.buffer.Write(b)
	}
	return 0, nil
}

func (w MockResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
}