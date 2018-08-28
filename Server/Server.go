package Server

import (
	"Preferences"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
	"gopkg.in/ldap.v2"
)

type Server struct {
	pref   *Preferences.Preference
	client *memcache.Client
	tmpl   *template.Template
}

func (s *Server) LoadPref(pref *Preferences.Preference) {
	fmt.Println("api_srvtosmb: 1: ")
	s.pref = pref
	s.client = memcache.New(s.pref.MemcachedServer + ":" + strconv.Itoa(s.pref.MemcachedPort))
	fmt.Println("api_srvtosmb: 2: ")

	fmt.Println("api_srvtosmb: 3: ")
	s.tmpl = template.New("answer")
}

func (s *Server) Server(w http.ResponseWriter, r *http.Request) {
	err := s.isAuth(r)
	if err != nil {
		err = s.Auth(r, &w)
		if err != nil {
			tmpl, err := s.tmpl.ParseFiles(s.pref.Template)
			data := struct {
				Success string
				Answer  string
			}{
				Success: "false",
				Answer:  "<Error>" + err.Error() + "</Error>",
			}
			tmpl.Execute(os.Stdout, data)
		}
	}
}

func (s *Server) isAuth(r *http.Request) error {
	cookie, err := r.Cookie("ident")
	if err != nil {
		fmt.Println("api_srvtosmb: isAuth error", err)
		return err
	}
	item, err := s.client.Get(cookie.String())
	if err != nil {
		fmt.Println("api_srvtosmb: isAuth error", err)
		return err
	}
	if r.RemoteAddr == string(item.Value) {
		return nil
	}
	return errors.New("not Auth")
}

func (s *Server) Auth(r *http.Request, w *http.ResponseWriter) error {
	header := r.Header
	s.tmpl.ParseFiles()
	Authorization := header.Get("Authorization")
	if Authorization == "" {
		fmt.Println("api_srvtosmb: Authorization: ", Authorization)
		fmt.Println("api_srvtosmb: Send: WWW-Authenticate")
		header.Add("WWW-Authenticate", "Basic")
		(*w).WriteHeader(401)
		return nil
	}
	strs := strings.Split(Authorization, " ")
	fmt.Println("api_srvtosmb: Authorization: ", Authorization)
	str, err := base64.StdEncoding.DecodeString(strs[1])
	if err != nil {
		//header.Add("WWW-Authenticate", "Basic")
		(*w).WriteHeader(403)
		return err
	}
	logpass := strings.Split(string(str), ":")
	fmt.Println("api_srvtosmb: Ldap Dial: ", err)
	fmt.Println(fmt.Sprintf("%s:%d", s.pref.LdapServer, s.pref.LdapPort))
	l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", s.pref.LdapServer, s.pref.LdapPort))
	if err != nil {
		/*fmt.Println("api_srvtosmb: Ldap: ", err)
		log.Fatal(err)
		header.Add("WWW-Authenticate", "Basic")*/
		(*w).WriteHeader(403)
		return err
	}
	defer l.Close()
	fmt.Println("api_srvtosmb: Ldap Ok: ", err)
	//err = l.Bind(s.pref.LdapUser, s.pref.LdapPassword)
	err = l.Bind(logpass[0]+"@"+s.pref.DomainName, logpass[1])
	if err != nil {
		fmt.Println("api_srvtosmb: Bind: ", err)
		fmt.Println("api_srvtosmb: s.pref.Template: ", s.pref.Template)
		s.PrintError(w, err)
		//(*w).Write([]byte("data.Answer"))
		//(*w).WriteHeader(401)
		return err
	}
	fmt.Println("api_srvtosmb: Bind Ok: ", err)
	searchRequest := ldap.NewSearchRequest(
		"OU=ATH,DC=ath,DC=ru",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(objectClass=person)(memberof:1.2.840.113556.1.4.1941:=CN=ftpadmin,OU=Services Accounts,OU=Moscow,OU=ATH,DC=ath,DC=ru)(|(sAMAccountName={username})(mail={username})))"),
		[]string{"sAMAccountName"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Fatal(err)
		fmt.Println("api_srvtosmb: Search: ", err)
		header.Add("WWW-Authenticate", "Basic")
		(*w).WriteHeader(403)
		return err
	}
	fmt.Println("api_srvtosmb: Search Ok: ", sr)
	for _, ent := range sr.Entries {
		if ent.GetAttributeValue("samAccountName") == logpass[0] {
			item := memcache.Item{}
			item.Key = StringWithCharset(20)
			item.Value = []byte(r.RemoteAddr)
			item.Expiration = 4 * 60 * 60
			s.client.Add(&item)
		}
	}
	fmt.Println("api_srvtosmb: Authorization: ", string(str))
	(*w).WriteHeader(200)
	return nil
}

func StringWithCharset(length int) string {
	charset := "abcdefghijklmnopqrstuvwxyz" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func (s *Server) PrintError(w *http.ResponseWriter, Error error) {
	tmpl, _ := s.tmpl.ParseFiles(s.pref.Template)
	fmt.Println("api_srvtosmb: s.tmpl: ", s.tmpl)

	data := struct {
		Success string
		Answer  string
	}{
		Success: "false",
		Answer:  "<Error>" + Error.Error() + "</Error>",
	}
	fmt.Println("api_srvtosmb: data: ", data)
	fmt.Println("api_srvtosmb: Bind data: ", data)
	tmpl.Execute(os.Stdout, data)
	fmt.Println("api_srvtosmb: os.Stdout: ", os.Stdout)
	fmt.Println("api_srvtosmb: data: ", data)
	//tmpl.Execute(*w, data)

}
