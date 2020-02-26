package samlmodule

import (
	"crypto/tls"
	"fmt"
	securityprotocol "github.com/KvalitetsIT/gosecurityprotocol"
	gosamlserviceprovider "gosamlserviceprovider/samlprovider"
	"net/http"
	"strconv"

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

	SessionHeaderName   string `json:"session_header_name,omitempty"`
	SessionExpiryHours  string `json:"session_expiry_hours,omitempty"`
	AudienceRestriction string `json:"audience_restriction,omitempty"`

	EntityId string `json:"entityId,omitempty"`

	SignAuthnRequest string `json:"sign_authn_req,omitempty"`
	SignCertFile     string `json:"sign_cert_file,omitempty"`
	SignKeyFile      string `json:"sign_key_file,omitempty"`

	IdpMetaDataUrl string `json:"idp_metadata_url,omitempty"`

	ExternalUrl string `json:"external_url,omitempty"`

	MetadataPath string `json:"metadata_path,omitempty"`
	LogoutPath   string `json:"logout_path,omitempty"`
	SLOPath      string `json:"slo_path,omitempty"`
	SSOPath      string `json:"sso_path,omitempty"`
	CookieDomain string `json:"cookie_domain,omitempty"`
	CookiePath   string `json:"cookie_path,omitempty"`

	SamlProvider *gosamlserviceprovider.SamlServiceProvider

	Logger *zap.SugaredLogger
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m SamlProviderModule) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {

	nextService := new(CaddyService)
	nextService.Handler = next

	httpCode, err := m.SamlProvider.HandleService(w, r, nextService)
	if httpCode != http.StatusOK {
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
		Name: "http.handlers.samlprovider",
		New:  func() caddy.Module { return new(SamlProviderModule) },
	}
}

// Provision implements caddy.Provisioner.
func (m *SamlProviderModule) Provision(ctx caddy.Context) error {
	m.Logger = ctx.Logger(m).Sugar()
	m.Logger.Info("Provisioning SamlProvidermodule")
	// Create Mongo Session Cache
	mongo_port := "27017"
	if len(m.MongoPort) != 0 {
		_, conv_err := strconv.Atoi(m.MongoPort)
		if conv_err != nil {
			return conv_err
		}
		mongo_port = m.MongoPort
	}
	mongo_url := fmt.Sprintf("%s:%s", m.MongoHost, mongo_port)
	m.Logger.Debugf("Using MongoDB:%s", mongo_url)
	sessionCache, err := securityprotocol.NewMongoSessionCache(mongo_url, m.MongoDb, "samlsessions")
	if err != nil {
		m.Logger.Warnf("Can't setup sessionCache: %v", err)
		return err
	}

	samlProviderConfig := new(gosamlserviceprovider.SamlServiceProviderConfig)
	samlProviderConfig.SignAuthnRequest, _ = strconv.ParseBool(m.SignAuthnRequest)
	m.Logger.Info("Loading keystore")
	keystore, err := tls.LoadX509KeyPair(m.SignCertFile, m.SignKeyFile)
	if err != nil {
		m.Logger.Errorf("Cannot load Keystore: %v", err)
	}
	samlProviderConfig.ServiceProviderKeystore = &keystore
	samlProviderConfig.EntityId = m.EntityId
	samlProviderConfig.ExternalUrl = m.ExternalUrl
	samlProviderConfig.CookieDomain = m.CookieDomain
	samlProviderConfig.CookiePath = m.CookiePath
	samlProviderConfig.AudienceRestriction = m.AudienceRestriction
	samlProviderConfig.IdpMetaDataUrl = m.IdpMetaDataUrl
	samlProviderConfig.SessionHeaderName = m.SessionHeaderName
	samlProviderConfig.SamlMetadataPath = m.MetadataPath
	samlProviderConfig.SamlLogoutPath = m.LogoutPath
	samlProviderConfig.SamlSLOPath = m.SLOPath
	samlProviderConfig.SamlSSOPath = m.SSOPath
	samlProviderConfig.SessionExpiryHours = m.SessionExpiryHours
	samlProviderConfig.Logger = m.Logger
	m.Logger.Infof("Starting SAML provider with config: %v", samlProviderConfig)
	m.SamlProvider, _ = gosamlserviceprovider.NewSamlServiceProviderFromConfig(samlProviderConfig, sessionCache)
	return nil
}

// Validate implements caddy.Validator.
func (m *SamlProviderModule) Validate() error {
	m.Logger.Info("Validating module")
	if len(m.MongoHost) == 0 {
		return fmt.Errorf("mongo_host must be configured")
	}

	if len(m.MongoDb) == 0 {
		return fmt.Errorf("mongo_db must be configured")
	}

	//TODO validation of all required elements
	return nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *SamlProviderModule) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	m.Logger.Info("Parsing module")
	for d.Next() {
		//if !d.Args(&m.Output) {
		//	return d.ArgErr()
		//}
	}
	return nil
}

// parseCaddyfile unmarshals tokens from h into a new Middleware.
func parseCaddyfileSamlProvider(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m SamlProviderModule
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

// Interface guards
var (
	_ caddy.Provisioner           = (*SamlProviderModule)(nil)
	_ caddy.Validator             = (*SamlProviderModule)(nil)
	_ caddyhttp.MiddlewareHandler = (*SamlProviderModule)(nil)
	_ caddyfile.Unmarshaler       = (*SamlProviderModule)(nil)
)
