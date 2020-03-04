package prometheus

import (
	"github.com/prometheus/client_golang/prometheus"
	metrics "github.com/prometheus/client_model/go"
	"go.uber.org/zap"
	"gotest.tools/assert"
	"net/http"
	"net/url"
	"testing"
)

var (
	module         PrometheusModule
	metricsHandler CountingHandler
	nextHandler    *CountingCaddyHandler
)

func setup() {
	module = PrometheusModule{}
	module.SetupMetrics()
	module.Logger = zap.NewNop().Sugar()
	module.MetricsPath = "/metricsPath"
	metricsHandler = CountingHandler{0}
	module.MetricsHandler = &metricsHandler
	nextHandler = &CountingCaddyHandler{0}
}

func TestPrometheusModule(t *testing.T) {
	setup()
	t.Run("Test metrics Path", testMetricsPath)
	metricsHandler.reset()
	nextHandler.reset()
	t.Run("Test other Path", testOtherPath)
	metricsHandler.reset()
	nextHandler.reset()
	t.Run("More calls increment metrics", testMultipleCalls)

}

func testMetricsPath(t *testing.T) {
	r := &http.Request{}
	url, _ := url.Parse("/metricsPath")
	r.URL = url
	r.Proto = "https"
	r.Host = "localhost"
	r.Method = "GET"
	w := MockResponseWriter{}
	module.ServeHTTP(w, r, nextHandler)
	assert.Equal(t, 0, nextHandler.calls)
	assert.Equal(t, 1, metricsHandler.Calls)
	metrics, _ := prometheus.DefaultGatherer.Gather()
	rcMetric := extractMetric(metrics, "requests_count", Label{"path", "/metricsPath"})
	assert.Equal(t, 1, int(*rcMetric.Counter.Value))
	rtMetric := extractMetric(metrics, "response_time", Label{"path", "/metricsPath"})
	assert.Equal(t, 1, int(*rtMetric.Histogram.SampleCount))

}

func testOtherPath(t *testing.T) {
	r := &http.Request{}
	url, _ := url.Parse("/anotherPath")
	r.URL = url
	r.Proto = "https"
	r.Host = "localhost"
	r.Method = "GET"
	w := MockResponseWriter{}
	module.ServeHTTP(w, r, nextHandler)
	assert.Equal(t, 1, nextHandler.calls)
	assert.Equal(t, 0, metricsHandler.Calls)
	metrics, _ := prometheus.DefaultGatherer.Gather()
	rcMetric := extractMetric(metrics, "requests_count", Label{"path", "/anotherPath"})
	assert.Equal(t, 1, int(*rcMetric.Counter.Value))
	rtMetric := extractMetric(metrics, "response_time", Label{"path", "/anotherPath"})
	assert.Equal(t, 1, int(*rtMetric.Histogram.SampleCount))

}

func testMultipleCalls(t *testing.T) {
	r := &http.Request{}
	path := "/multiplePath"
	url, _ := url.Parse(path)
	r.URL = url
	r.Proto = "https"
	r.Host = "localhost"
	r.Method = "GET"
	w := MockResponseWriter{}
	count := 10
	for i := 0; i < count; i++ {
		module.ServeHTTP(w, r, nextHandler)
	}
	assert.Equal(t, 0, metricsHandler.Calls)
	assert.Equal(t, count, nextHandler.calls)
	metrics, _ := prometheus.DefaultGatherer.Gather()
	rcMetric := extractMetric(metrics, "requests_count", Label{"path", path})
	assert.Equal(t, count, int(*rcMetric.Counter.Value))
	rtMetric := extractMetric(metrics, "response_time", Label{"path", path})
	assert.Equal(t, count, int(*rtMetric.Histogram.SampleCount))

}

//Utils
func extractMetric(metrics []*metrics.MetricFamily, name string, pair Label) *metrics.Metric {
	for _, mf := range metrics {
		if *mf.Name == name {
			for _, m := range mf.Metric {
				for _, l := range m.GetLabel() {
					if l.GetName() == pair.Name && l.GetValue() == pair.Value {
						return m
					}
				}
			}
		}
	}
	return nil
}

type Label struct {
	Name  string
	Value string
}

type CountingHandler struct {
	Calls int
}

func (h *CountingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	h.Calls++
}

func (h *CountingHandler) reset() {
	h.Calls = 0
}

type CountingCaddyHandler struct {
	calls int
}

func (h *CountingCaddyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	w.WriteHeader(http.StatusOK)
	h.calls = h.calls + 1
	return nil
}

func (h *CountingCaddyHandler) reset() {
	h.calls = 0
}

type MockResponseWriter struct {
	statusCode int
	headers    http.Header
}

func (w MockResponseWriter) Header() http.Header {
	return w.headers
}

func (w MockResponseWriter) Write([]byte) (int, error) {
	return 0, nil
}

func (w MockResponseWriter) WriteHeader(statusCode int) {

}
