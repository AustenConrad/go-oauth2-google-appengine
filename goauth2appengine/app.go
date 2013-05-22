package goauth2appengine

import (
	"appengine"
	"appengine/urlfetch"
	"code.google.com/p/goauth2/oauth"
	"html/template"
	"net/http"
)

// Cache all of the HTML files in the templates directory so that we only have to hit disk once.
var cached_templates = template.Must(template.ParseGlob("goauth2appengine/templates/*.html"))

// Global Variables used during OAuth protocol flow of authentication.
var (
	code  = ""
	token = ""
)

// OAuth2 configuration.
var oauthCfg = &oauth.Config{
	// TODO: put your project's Client Id from https://code.google.com/apis/console here.
	ClientId: "TODO",

	// TODO: put your project's Client Secret from https://code.google.com/apis/console here.
	ClientSecret: "TODO",

	// Google's OAuth2 authentication URL.
	AuthURL: "https://accounts.google.com/o/oauth2/auth",

	// To return your OAuth2 code, Google will redirect the browser to this page that you have defined.
	// TODO: This exact URL should also be added in your Google API console for this project within "API Access"->"Redirect URIs"
	RedirectURL: "http://[your domain or localhost]/oauth2callback",

	// Google's OAuth2 token URL.
	TokenURL: "https://accounts.google.com/o/oauth2/token",

	// This is the 'scope' of the data that you are asking the user's permission to access. For getting user's info, this is the URL that Google has defined.
	Scope: "https://www.googleapis.com/auth/userinfo.profile",
}

// This is the URL that Google has defined so that an authenticated application may obtain the user's info in json format.
const profileInfoURL = "https://www.googleapis.com/oauth2/v1/userinfo?alt=json"

// This is where Google App Engine sets up which handler lives at the root url.
func init() {
	// Immediately enter the main app.
	main()
}

func main() {

	// Setup application handlers.
	http.HandleFunc("/", handleRoot)
	http.HandleFunc("/authorize", handleAuthorize)

	// Google will redirect to this page to return your code, so handle it appropriately
	http.HandleFunc("/oauth2callback", handleOAuth2Callback)

}

// Root directory handler.
func handleRoot(rw http.ResponseWriter, req *http.Request) {

	err := cached_templates.ExecuteTemplate(rw, "notAuthenticated.html", nil)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusNotFound)
	}

}

// Start the authorization process.
func handleAuthorize(rw http.ResponseWriter, req *http.Request) {

	// Get the Google URL which shows the Authentication page to the user.
	url := oauthCfg.AuthCodeURL("")

	// Redirect user to that page.
	http.Redirect(rw, req, url, http.StatusFound)
}

// Function that handles the callback from the Google server.
func handleOAuth2Callback(rw http.ResponseWriter, req *http.Request) {

	// Initialize an appengine context.
	c := appengine.NewContext(req)

	// Retrieve the code from the response.
	code := req.FormValue("code")

	// Configure OAuth's http.Client to use the appengine/urlfetch transport that all Google App Engine applications have to use for outbound requests.
	t := &oauth.Transport{Config: oauthCfg, Transport: &urlfetch.Transport{Context: c}}

	// Exchange the received code for a token.
	token, err := t.Exchange(code)
	if err != nil {
		c.Errorf("%v", err)
	}

	// Now get user data based on the Transport which has the token.
	resp, _ := t.Client().Get(profileInfoURL)
	buf := make([]byte, 1024)
	resp.Body.Read(buf)

	// Log the token.
	c.Infof("Token: %s", token)

	// Render the user's information.
	err = cached_templates.ExecuteTemplate(rw, "userInfo.html", string(buf))
	if err != nil {
		http.Error(rw, err.Error(), http.StatusNotFound)
	}
}
