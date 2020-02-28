package prometheus

import "net/http"

type PrometheusResponseWriter struct {
	statusCode int
	writer     http.ResponseWriter
}

func NewPrometheusResponseWriter(writer http.ResponseWriter) *PrometheusResponseWriter {
	return &PrometheusResponseWriter{http.StatusOK, writer}
}

func (pw PrometheusResponseWriter) Header() http.Header {
	return pw.writer.Header()
}

func (pw PrometheusResponseWriter) Write(b []byte) (int, error) {
	return pw.writer.Write(b)
}

func (pw PrometheusResponseWriter) WriteHeader(statusCode int) {
	pw.statusCode = statusCode
	pw.writer.WriteHeader(statusCode)
}
