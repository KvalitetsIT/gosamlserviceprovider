package prometheus

import (
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"net/http"
	"strconv"
	"time"
)

type PrometheusModule struct {
	MetricsPath    string `json:"metrics_path,omitempty"`
	MetricsHandler http.Handler
	Logger         *zap.SugaredLogger
	labels         []string
}

var (
	requestCount    *prometheus.CounterVec
	responseLatency *prometheus.HistogramVec
	//Interface guards
	_ caddy.Provisioner           = (*PrometheusModule)(nil)
	_ caddy.Validator             = (*PrometheusModule)(nil)
	_ caddyhttp.MiddlewareHandler = (*PrometheusModule)(nil)
	_ caddyfile.Unmarshaler       = (*PrometheusModule)(nil)
)

func (m PrometheusModule) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	start := time.Now()
	writer := NewPrometheusResponseWriter(w)
	var result error = nil
	if r.URL.Path == m.MetricsPath {
		m.Logger.Debugf("Returning metrics on path %v", r.URL.Path)
		m.MetricsHandler.ServeHTTP(writer, r)
	} else {
		m.Logger.Debugf("Forwarding path %v to next handler", r.URL.Path)
		result = next.ServeHTTP(writer, r)
	}
	duration := time.Since(start)
	requestCount.WithLabelValues(m.labelValues(writer, r)...).Inc()
	responseLatency.WithLabelValues(m.labelValues(writer, r)...).Observe(duration.Seconds())
	return result
}

func (m PrometheusModule) labelValues(w *PrometheusResponseWriter, r *http.Request) []string {
	proto := r.Proto
	host := r.Host
	path := r.URL.Path
	method := r.Method
	status := strconv.Itoa(w.statusCode)
	return []string{host, proto, method, path, status}
}

func init() {
	caddy.RegisterModule(PrometheusModule{})
	httpcaddyfile.RegisterHandlerDirective("prometheus", parseCaddyfilePrometheus)
}

// CaddyModule returns the Caddy module information.
func (PrometheusModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "http.handlers.prometheus",
		New:  func() caddy.Module { return new(PrometheusModule) },
	}
}

// Provision implements caddy.Provisioner.
func (m *PrometheusModule) Provision(ctx caddy.Context) error {
	m.Logger = ctx.Logger(m).Sugar()
	//TODO read these from configuration
	m.SetupMetrics()

	m.MetricsHandler = promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{
		ErrorHandling: promhttp.HTTPErrorOnError,
		ErrorLog:      NewErrorLogger(m.Logger),
	})

	return nil
}

func (m *PrometheusModule) SetupMetrics() {
	m.labels = []string{"host", "protocol", "method", "path", "status"}
	requestCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "requests_count",
		Help: "Counts number of HTTP requests",
	}, m.labels)

	responseLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "response_time",
		Help: "Histogram the response latency in seconds",
	}, m.labels)

	prometheus.MustRegister(requestCount)
	prometheus.MustRegister(responseLatency)
}

// Validate implements caddy.Validator.
func (m *PrometheusModule) Validate() error {
	m.Logger.Info("Validating module")
	if len(m.MetricsPath) == 0 {
		return fmt.Errorf("metrics_path must be configured")
	}
	return nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *PrometheusModule) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	m.Logger.Info("Parsing module")
	for d.Next() {
		//if !d.Args(&m.Output) {
		//	return d.ArgErr()
		//}
	}
	return nil
}

// parseCaddyfile unmarshals tokens from h into a new Middleware.
func parseCaddyfilePrometheus(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m PrometheusModule
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}
