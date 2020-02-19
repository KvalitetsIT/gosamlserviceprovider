package gosamlserviceprovider

import (
	"encoding/xml"
	"fmt"
	securityprotocol "github.com/KvalitetsIT/gosecurityprotocol"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"net/http"
	"net/url"
	"strings"
)

type SamlHandler struct {
	callbackUrl    string
	logoutUrl      string
	metadataUrl    string
	sloCallbackUrl string

	cookieDomain string
	cookiePath   string

	sessionHeaderName string

	provider *SamlServiceProvider
	Logger   *zap.SugaredLogger
}

func NewSamlHandler(config *SamlServiceProviderConfig, provider *SamlServiceProvider) *SamlHandler {
	s := new(SamlHandler)
	s.callbackUrl = config.SamlCallbackUrl
	s.logoutUrl = config.SamlLogoutUrl
	s.metadataUrl = config.SamlMetadataUrl
	sloUrl, err := url.Parse(config.SLOConsumerServiceUrl)
	if err != nil {
		config.Logger.Warnf("Unable to parse SLO URL: %v", err)
	}
	s.sloCallbackUrl = sloUrl.Path
	s.cookieDomain = config.CookieDomain
	s.cookiePath = config.CookiePath
	s.sessionHeaderName = config.SessionHeaderName

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
	if strings.HasPrefix(r.URL.Path, handler.sloCallbackUrl) {
		return true
	}
	return false
}

func (handler *SamlHandler) GetSessionId(r *http.Request) (string, error) {
	sessionId := r.Header.Get(handler.sessionHeaderName)
	cookie, _ := r.Cookie(handler.sessionHeaderName)
	if sessionId != "" {
		return sessionId, nil
	}
	if cookie != nil {
		return cookie.Value, nil
	}
	return "", nil
}

func (handler *SamlHandler) Handle(w http.ResponseWriter, r *http.Request) (int, error) {
	if strings.HasPrefix(r.URL.Path, handler.callbackUrl) {
		//TODO test for HTTP METHOD = POST
		handler.Logger.Infof("Handling login callback")
		return handler.handleSamlLoginResponse(w, r)
	}

	if strings.HasPrefix(r.URL.Path, handler.metadataUrl) {
		//TODO test for HTTP METHOD = GET
		handler.Logger.Infof("Handling metadata")
		return handler.handleMetadata(w, r)
	}

	if strings.HasPrefix(r.URL.Path, handler.logoutUrl) {
		handler.Logger.Infof("Handling logout")
		return handler.handleSLO(r, w)

	}
	if strings.HasPrefix(r.URL.Path, handler.sloCallbackUrl) {
		handler.Logger.Infof("Handling logout callback")
		return handler.handleSLOCallback(r, w)

	}
	return http.StatusOK, nil
}

func (handler *SamlHandler) handleSLOCallback(r *http.Request, w http.ResponseWriter) (int, error) {
	sessionId, err := handler.GetSessionId(r)
	if err != nil {
		handler.Logger.Warnf("Unable to extraxt sessionID from request: %v", err)
		return http.StatusInternalServerError, err
	}
	if sessionId == "" {
		handler.Logger.Warnf("No sessionId provided for logout")
		return http.StatusBadRequest, nil
	}
	cookie := http.Cookie{
		Name:     handler.sessionHeaderName,
		MaxAge:   -1,
		Path:     "/",
		HttpOnly: true,
	}
	http.SetCookie(w, &cookie)
	handler.provider.sessionCache.DeleteSessionData(sessionId)
	fmt.Fprintf(w, "You are succesfully logged out")
	handler.Logger.Infof("Logging out session: %s ", sessionId)
	return http.StatusOK, nil
}

func (handler *SamlHandler) handleSLO(r *http.Request, w http.ResponseWriter) (int, error) {
	sessionId, err := handler.GetSessionId(r)
	if err != nil {
		handler.Logger.Warnf("Unable to extraxt sessionID from request: %v", err)
		return http.StatusInternalServerError, err
	}
	if sessionId == "" {
		handler.Logger.Warnf("No sessionId provided for logout")
		return http.StatusBadRequest, nil
	}
	handler.Logger.Infof("Logging out session: %s ", sessionId)
	session, err := handler.provider.sessionCache.FindSessionDataForSessionId(sessionId)
	if err != nil {
		handler.Logger.Warnf("Cannot lookup session: %v", err)
		return http.StatusInternalServerError, err
	}
	if session == nil {
		handler.Logger.Warnf("No session found for id: %v", sessionId)
		return http.StatusInternalServerError, err
	}
	nameIDs := session.UserAttributes["NameID"]
	if nameIDs == nil || len(nameIDs) != 1 {
		handler.Logger.Warnf("NameID not found on session")
		return http.StatusInternalServerError, err
	}
	sessionIndex := session.SessionAttributes["SessionIndex"]
	if sessionIndex == "" {
		handler.Logger.Warnf("SessionIndex not found on session")
		return http.StatusInternalServerError, err
	}
	handler.Logger.Infof("Build logoutrequest with NameID: %s SessionIndex: %s", nameIDs[0], sessionIndex)
	logoutRequestDocument, _ := handler.provider.SamlServiceProvider.BuildLogoutRequestDocument(nameIDs[0], sessionIndex)
	logoutURLRedirect, _ := handler.provider.SamlServiceProvider.BuildLogoutURLRedirect("", logoutRequestDocument)
	http.Redirect(w, r, logoutURLRedirect, http.StatusFound)
	return http.StatusFound, nil
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
		handler.Logger.Warnf("Error parsing form data: %v", err)
		return http.StatusBadRequest, nil
	}

	assertionInfo, err := handler.provider.SamlServiceProvider.RetrieveAssertionInfo(r.FormValue("SAMLResponse"))
	if err != nil {
		handler.Logger.Warnf("Invalid assertions: %v", err)
		fmt.Fprintf(w, "Invalid assertions: %s", err.Error())
		return http.StatusForbidden, nil
	}
	if assertionInfo.WarningInfo.InvalidTime {
		handler.Logger.Warnf("Invalid assertions: %v", "InvalidTime")
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
	//TODO shouldn't these be saved in the SAMLSessionDataCreator module??
	sessionData.UserAttributes["NameID"] = []string{assertionInfo.NameID}
	sessionData.SessionAttributes["SessionIndex"] = assertionInfo.SessionIndex
	if err != nil {
		fmt.Println("Error creating sessionData: " + err.Error())
		return http.StatusBadRequest, nil
	}
	handler.Logger.Infof("SessionData saved for id: %v => %v", sessionData.Sessionid, sessionData.UserAttributes)

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
	http.Redirect(w, r, relayState, http.StatusFound)
	return http.StatusFound, nil
}
