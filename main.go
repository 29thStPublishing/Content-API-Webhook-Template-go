package main

import (
        "encoding/json"
        "errors"
        "flag"
        "log"
        "io/ioutil"
        "net/http"
        "os"
        "github.com/codegangsta/negroni"
        "gopkg.in/dgrijalva/jwt-go.v3"
        "fmt"
)

var (
        ip   = flag.String("ip", "0.0.0.0", "ip to listen on")
        port = flag.Int("port", 8787, "port to listen on")
        verbose = flag.Bool("v", false, "show verbose log output")
)

const serverKey string = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2m9Nvgfa2c45/ONegCf7
QxyQPE3ffTT0Jxs1Uc/huw5VQ1fwz/laiUs+Cc70O2OhE8fWs8IWiztnw1Hsebya
NwrdBEtoK7yLffM8Fwu73icwfg7XeLPdSgxbRqQ33nTyG73Z683R7YQGmyEWLan7
STgi6ijh8sfh+aYThqb5xd5sAFBu0o00yIasa0+xERRf0XJchUeu0c1VCgrcFJ6P
uAXjZWpiEDEKBfZgeepTy0aApnJH4AsxPjZkP6mXtGajDYimlf/3Hw4mvxTJ/Cmc
QjtuOBWGxB8NDyOJ4Hd31j2EawT1vyTLjp5smZ5kQZt1QFxmtKbVlSifW6lUDOg3
NQIDAQAB
-----END PUBLIC KEY-----
`

// Hook - A Content API Webhook
type Hook struct {
        Magazine        string  `json:"magazine"`
        Method          string  `json:"method"`
        Token           string  `json:"jwt"`
        EntryID         string  `json:"entryId"`
        Collection      string  `json:"collection"`
        Data    map[string]interface{}  `json:"data"`
}

func newHook() *Hook {
        data := make(map[string]interface{})
        return &Hook{Data: data}
}

func main() {
        flag.Parse()
        log.SetPrefix("[content-api-hook] ")
        log.SetFlags(log.Ldate | log.Ltime)
        if !*verbose {
		log.SetOutput(ioutil.Discard)
	}
        log.Println("webhook server starting")
        l := negroni.NewLogger()
	l.ALogger = log.New(os.Stderr, "[content-api-hook] ", log.Ldate|log.Ltime)
        negroniRecovery := &negroni.Recovery{
		Logger:     l.ALogger,
		PrintStack: true,
		StackAll:   false,
		StackSize:  1024 * 8,
	}

	n := negroni.New(negroniRecovery, l)

        http.HandleFunc("/webhook", http.HandlerFunc(webhookHandler))
	n.UseHandler(http.HandlerFunc(webhookHandler))
        log.Printf("listening at http://%s:%d/webhook", *ip, *port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%d", *ip, *port), n))
}

func webhookHandler(w http.ResponseWriter, r *http.Request) {
        if r.Method != "POST" {
                http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
                return
        }
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("error reading the request body. %+v\n", err)
                return
	}

        webhook := newHook()
        err = json.Unmarshal(body, &webhook)
	if err != nil {
		log.Printf("error parsing JSON payload %+v\n", err)
                return
	}
        log.Println("webhook received successfully!")

        err = checkJWT(webhook.Token, serverKey)
        if err != nil {
                log.Println("JWT validation failed", err)
                http.Error(w, "Invalid token", http.StatusUnauthorized)
                return
	}

        /*
        Handle webhook here
        */

}

func checkJWT(jwtToken string, k string) error {
        key, err := jwt.ParseRSAPublicKeyFromPEM([]byte(k))
        if err != nil {
                log.Println("HERE?")
                return err
        }

        token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
                if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
                        return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
                }
                return key, nil
        })
        if err != nil {
                return err
        }

        if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
                if claims["iss"] != "https://api.29.io" {
                        return errors.New("Bad issuer in token")
                }
        } else {
                return errors.New("Invalid token")
        }
        return nil
}
