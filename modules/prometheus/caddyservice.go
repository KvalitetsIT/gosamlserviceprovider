package prometheus

import "github.com/caddyserver/caddy/v2/modules/caddyhttp"
import "net/http"

type CaddyService struct {
	Handler caddyhttp.Handler
}

func (c CaddyService) Handle(w http.ResponseWriter, r *http.Request) (int, error) {
	serviceErr := c.Handler.ServeHTTP(w, r)
	// the problem is in the err
	return http.StatusOK, serviceErr
}
