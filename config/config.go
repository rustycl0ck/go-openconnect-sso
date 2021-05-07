package config

import "encoding/xml"

/*******************************************************
Initialization XML Response
**********************************************
  <?xml version="1.0" encoding="UTF-8"?>
  <config-auth some="attr">
    <opaque another="attr">
      <tunnel-group>Profile_Name</tunnel-group>
      <auth-method>single-sign-on-v2</auth-method>
      <config-hash>1234567890123</config-hash>
    </opaque>
    <auth id="main">
      <title>Login</title>
      <message>Some useful message for the user to inform about next step for login</message>
      <banner></banner>
      <sso-v2-login>https://vpn.server.myorg.com/path/to/login/page</sso-v2-login>
      <sso-v2-login-final>https://vpn.server.myorg.com/login/successful/page</sso-v2-login-final>
      <sso-v2-token-cookie-name>someCookieNameWhichContainsToken</sso-v2-token-cookie-name>
      <sso-v2-error-cookie-name>someCookieNameWhichContainsError</sso-v2-error-cookie-name>
      <form>
        <input type="sso" name="sso-token"></input>
      </form>
    </auth>
  </config-auth>"
*******************************************************/
type InitializationResponse struct {
	XMLName         xml.Name `xml:"config-auth"`
	LoginURL        string   `xml:"auth>sso-v2-login"`
	LoginFinalURL   string   `xml:"auth>sso-v2-login-final"`
	TokenCookieName string   `xml:"auth>sso-v2-token-cookie-name"`
	Opaque          struct {
		Value string `xml:",innerxml"`
	} `xml:"opaque"`
}

type FinalizationResponse struct {
	XMLName     xml.Name `xml:"config-auth"`
	Cookie      string   `xml:"session-token"`
	Fingerprint string   `xml:"config>vpn-base-config>server-cert-hash"`
}

/*******************************************************
Finalization XML Response
**********************************************
  <?xml version="1.0" encoding="UTF-8"?>
  <config-auth client="vpn" type="complete" aggregate-auth-version="2">
    <session-id>2345678901234</session-id>
    <session-token>somelongrandomtokenhere</session-token>
    <auth id="success">
      <banner>Some useful pop up message after successful login</banner>
    </auth>
    <config attr1="val1">
      <vpn-base-config>
        <server-cert-hash>0123456789ABCDEF0123</server-cert-hash>
      </vpn-base-config>
    </config>
  </config-auth>
*******************************************************/
