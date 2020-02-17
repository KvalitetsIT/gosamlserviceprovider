package gosamlserviceprovider

import (
	"encoding/xml"
	"fmt"
	securityprotocol "github.com/KvalitetsIT/gosecurityprotocol"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"net/http"
	"strings"
)

type SamlHandler struct {
	callbackUrl string
	logoutUrl   string
	metadataUrl string
	provider    *SamlServiceProvider
	Logger      *zap.SugaredLogger
}

func NewSamlHandler(config *SamlServiceProviderConfig, provider *SamlServiceProvider) *SamlHandler {
	s := new(SamlHandler)
	s.callbackUrl = config.SamlCallbackUrl
	s.logoutUrl = config.SamlLogoutUrl
	s.metadataUrl = config.SamlMetadataUrl
	s.provider = provider
	s.Logger = config.Logger
	return s
}

func (handler *SamlHandler) isSamlProtocol(r *http.Request) bool {
	if strings.HasPrefix(r.URL.Path, handler.callbackUrl) {
		return true
	}
	if strings.HasPrefix(r.URL.Path, handler.metadataUrl) {
		return true
	}
	if strings.HasPrefix(r.URL.Path, handler.logoutUrl) {
		return true
	}
	return false
}

func (handler *SamlHandler) Handle(w http.ResponseWriter, r *http.Request) (int, error) {
	// Indsæt tjek om det er en del af samlflow (via url /saml/SSO og /saml/metadata og /saml/logout)
	if strings.HasPrefix(r.URL.Path, handler.callbackUrl) {
		//TODO test for HTTP METHOD = POST
		return handler.handleSamlLoginResponse(w, r)
	}

	if strings.HasPrefix(r.URL.Path, handler.metadataUrl) {
		//TODO test for HTTP METHOD = GET
		return handler.handleMetadata(w, r)
	}

	if strings.HasPrefix(r.URL.Path, handler.logoutUrl) {
		return http.StatusOK, nil
	}
	return http.StatusOK, nil
}

func (handler *SamlHandler) handleMetadata(w http.ResponseWriter, r *http.Request) (int, error) {
	spMetadata, _ := handler.provider.SamlServiceProvider.Metadata()
	spMetadataXml, _ := xml.MarshalIndent(spMetadata, "", "")
	w.Write(spMetadataXml)
	return http.StatusOK, nil
}

func (handler *SamlHandler) handleSamlLoginResponse(w http.ResponseWriter, r *http.Request) (int, error) {
	err := r.ParseForm()
	if err != nil {
		fmt.Println("Error parsing form data: " + err.Error())
		return http.StatusBadRequest, nil
	}

	assertionInfo, err := handler.provider.SamlServiceProvider.RetrieveAssertionInfo(r.FormValue("SAMLResponse"))
	if err != nil {
		fmt.Fprintf(w, "Invalid assertions: %s", err.Error())
		return http.StatusForbidden, nil
	}
	if assertionInfo.WarningInfo.InvalidTime {
		fmt.Fprintf(w, "Invalid assertions: %s", "InvalidTime")
		return http.StatusForbidden, nil
	}
	if assertionInfo.WarningInfo.NotInAudience {
		fmt.Fprintf(w, "Invalid assertions: %s", "UserNotInAudience")
		return http.StatusForbidden, nil
	}

	assertionXml, _ := xml.Marshal(assertionInfo.Assertions[0])
	sessionDataCreator, err := securityprotocol.NewSamlSessionDataCreatorWithId(uuid.New().String(), string(assertionXml))
	if err != nil {
		fmt.Println("Error creating sessionData: " + err.Error())
		return http.StatusBadRequest, nil
	}
	sessionData, err := sessionDataCreator.CreateSessionData()
	if err != nil {
		fmt.Println("Error creating sessionData: " + err.Error())
		return http.StatusBadRequest, nil
	}
	handler.provider.sessionCache.SaveSessionData(sessionData)
	cookie := http.Cookie{
		Name:     handler.provider.sessionHeaderName,
		Value:    sessionData.Sessionid,
		Expires:  *assertionInfo.SessionNotOnOrAfter,
		Path:     "/",
		HttpOnly: true,
	}
	http.SetCookie(w, &cookie)
	w.Header().Add(handler.provider.sessionHeaderName, sessionData.Sessionid)
	relayState := r.FormValue("RelayState")
	w.Header().Add("Location", relayState)
	return http.StatusFound, nil
}
