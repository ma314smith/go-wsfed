package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/ma314smith/go-wsfed"
)

var config wsfed.Config
var sso *wsfed.WSFed

func main() {
	config = wsfed.Config{}
	config.MetadataURL = "https://signin.blackbaud.com/wsfederation/metadata"
	config.MetadataCertsAreTrusted = true
	config.MetadataRefreshIntervalSeconds = 10
	config.Realm = "http://account.blackbaud.com"
	sso = wsfed.New(&config)

	http.Handle("/", http.HandlerFunc(myFunc))
	fmt.Println("Listening on http://127.0.0.1:80")
	err := http.ListenAndServe(":80", nil)
	if err != nil {
		log.Fatal("ListenAndServe:", err)
	}
}

func myFunc(w http.ResponseWriter, r *http.Request) {
	wresult := r.PostFormValue("wresult")

	if wresult == "" {
		rp := sso.GetDefaultRequestParameters()
		rp.Wreply = "http://" + r.Host + r.URL.String()
		url, err := sso.GetRequestURL(rp)
		if err != nil {
			panic(err)
		}
		http.Redirect(w, r, url, 302)
		return
	}

	claims, err := sso.ParseResponse(wresult)
	if err != nil {
		w.Write([]byte(fmt.Sprintf("Error parsing response: %s", err)))
		//w.Write([]byte(wresult))
	} else {
		w.Write([]byte(fmt.Sprintf("Claims: %v", claims)))
		//w.Write([]byte(wresult))
	}
}
