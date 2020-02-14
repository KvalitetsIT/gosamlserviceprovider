package samlmodule

import (
	"fmt"
	gosamlserviceprovider "gosamlserviceprovider/samlprovider"
	"strconv"
	securityprotocol "github.com/KvalitetsIT/gosecurityprotocol"
//	"fmt"
//	"io"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	 "go.uber.org/zap"
)

const DEFAULT_VALUE_SESSION_HEADER_NAME = "SESSION"


type SamlProviderModule struct {


	MongoHost string `json:"mongo_host,omitempty"`

	MongoPort string `json:"mongo_port,omitempty"`

	MongoDb string `json:"mongo_db,omitempty"`

	SessionHeaderName string `json:"session_header_name,omitempty"`

	StsUrl string `json:"sts_url,omitempty"`

	ClientCertFile string `json:"client_cert_file,omitempty"`

	ClientKeyFile string `json:"client_key_file,omitempty"`

	TrustCertFiles []string `json:"trust_cert_files,omitempty"`

	ServiceEndpoint string `json:"service_endpoint,omitempty"`

	ServiceAudience string `json:"service_audience,omitempty"`

	SessionDataUrl string `json:"session_data_url,omitempty"`

	SamlProvider *gosamlserviceprovider.SamlServiceProvider

	Logger *zap.SugaredLogger
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m SamlProviderModule) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {

	nextService := new(CaddyService)
	nextService.Handler = next

	httpCode, err := m.SamlProvider.HandleService(w, r, nextService)
	if (httpCode != http.StatusOK) {
		return caddyhttp.Error(httpCode, err)
	}
	return err
}



func init() {
	caddy.RegisterModule(SamlProviderModule{})
	httpcaddyfile.RegisterHandlerDirective("samlprovider", parseCaddyfileSamlProvider)
}

// CaddyModule returns the Caddy module information.
func (SamlProviderModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		Name: "http.handlers.sam",
		New:  func() caddy.Module { return new(SamlProviderModule) },
	}
}

// Provision implements caddy.Provisioner.
func (m *SamlProviderModule) Provision(ctx caddy.Context) error {
    m.Logger = ctx.Logger(m).Sugar()
    m.Logger.Info("Provisioning SamlProvidermodule")
	// Create Mongo Session Cache
	mongo_port := "27017"
	if (len(m.MongoPort) != 0) {
		_, conv_err := strconv.Atoi(m.MongoPort)
        	if (conv_err != nil) {
                	return conv_err
        	}
		mongo_port = m.MongoPort
        }
	mongo_url := fmt.Sprintf("%s:%s", m.MongoHost, mongo_port)
	m.Logger.Debugf("Using MongoDB:%s", mongo_url)
	sessionCache, err := securityprotocol.NewMongoSessionCache(mongo_url, m.MongoDb, "samlsessions")
	if (err != nil) {
	    m.Logger.Warnf("Can't setup sessionCache: %v", err)
		return err
	}

    //TODO download SAML metadata file from URL
    samlProviderConfig := new(gosamlserviceprovider.SamlServiceProviderConfig)
        /*
        	ServiceProviderKeystore *tls.Certificate

        	EntityId string

        	AssertionConsumerServiceUrl string
        	AudienceRestriction         string

        	SignAuthnRequest bool

        	IdpMetaDataFile string

        	Service securityprotocol.HttpHandler
        */
        samlProviderConfig.SessionHeaderName = DEFAULT_VALUE_SESSION_HEADER_NAME
        samlProviderConfig. = m.AudienceRestriction
    //TODO make rest of configuration

	m.SamlProvider = gosamlserviceprovider.NewSamlServiceProviderFromConfig(samlProviderConfig, sessionCache,m.logger)
	return nil
}

// Validate implements caddy.Validator.
func (m *CaddyOioIdwsRestWsc) Validate() error {

	if (len(m.MongoHost) == 0) {
		return fmt.Errorf("mongo_host must be configured")
	}

        if (len(m.MongoDb) == 0) {
                return fmt.Errorf("mongo_db must be configured")
        }

        if (len(m.StsUrl) == 0) {
                return fmt.Errorf("sts_url must be configured")
        }

        if (len(m.ServiceEndpoint) == 0) {
                return fmt.Errorf("service_endpoint must be configured")
        }

	return nil
}


// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *CaddyOioIdwsRestWsc) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		//if !d.Args(&m.Output) {
		//	return d.ArgErr()
		//}
	}
	return nil
}

// parseCaddyfile unmarshals tokens from h into a new Middleware.
func parseCaddyfileWsc(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m CaddyOioIdwsRestWsc
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

// Interface guards
var (
	_ caddy.Provisioner              = (*CaddyOioIdwsRestWsc)(nil)
	_ caddy.Validator                = (*CaddyOioIdwsRestWsc)(nil)
	_ caddyhttp.MiddlewareHandler    = (*CaddyOioIdwsRestWsc)(nil)
	_ caddyfile.Unmarshaler          = (*CaddyOioIdwsRestWsc)(nil)
)
