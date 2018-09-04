package Server

import (
	"Preferences"
	"database/sql"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
	_ "github.com/go-sql-driver/mysql"
	"gopkg.in/ldap.v2"
)

type Server struct {
	pref   *Preferences.Preference
	client *memcache.Client
	db     *sql.DB
}

func (s *Server) LoadPref(pref *Preferences.Preference) {
	s.pref = pref
	s.client = memcache.New(s.pref.MemcachedServer + ":" + strconv.Itoa(s.pref.MemcachedPort))
	db, err := sql.Open("mysql",
		fmt.Sprintf("%s:%s@tcp(%s)/%s?charset=utf8",
			s.pref.UserMySql, s.pref.PasswordMySql, s.pref.Address, s.pref.DatabaseMySql))
	s.db = db
	if err != nil {
		fmt.Println("main: db error: ", err)
		return
	}
}

func (s *Server) Server(w http.ResponseWriter, r *http.Request) {
	err := s.isAuth(r)
	if err != nil {
		err = s.Auth(r, w)
		if err != nil {
			s.PrintError(&w, err, 403)
			return
		}
	}
	values := r.URL.Query()
	if _, err := values["username"]; err {
	} else {
		s.PrintError(&w, errors.New("value user not found"), 407)
	}
	switch r.Method {
	case "GET":
		fmt.Println("api_srvtosmb: ", values)
		s.GetUserInfo(values["username"], w)
	case "POST":
		s.PostUserInfo(values, w)
	case "PUT":
		s.CreateUser(values, w)
	case "DELETE":
		s.DeleteUser(w, values)
	case "LOCK":
		s.LockUnlockUser(w, values["username"][0], true)
	case "UNLOCK":
		s.LockUnlockUser(w, values["username"][0], false)
	}
}

func (s *Server) isAuth(r *http.Request) error {
	cookie, err := r.Cookie("ident")
	if err != nil {
		fmt.Println("api_srvtosmb: isAuth error", err)
		return err
	}
	fmt.Println("cookie.String: ", cookie.Value)
	item, err := s.client.Get(cookie.Value)
	if err != nil {
		fmt.Println("api_srvtosmb: isAuth error", err)
		return err
	}
	if r.RemoteAddr == string(item.Value) {
		fmt.Println("api_srvtosmb: isAuth error", r.RemoteAddr, string(item.Value))
		return nil
	}
	return errors.New("not Auth")
}

func (s *Server) Auth(r *http.Request, w http.ResponseWriter) error {
	header := r.Header
	Authorization := header.Get("Authorization")
	if Authorization == "" {
		fmt.Println("api_srvtosmb: Authorization: ", Authorization)
		fmt.Println("api_srvtosmb: Send: WWW-Authenticate")
		w.Header().Add("WWW-Authenticate", "Basic")
		w.WriteHeader(401)
		return nil
	}
	strs := strings.Split(Authorization, " ")
	fmt.Println("api_srvtosmb: Authorization: ", Authorization)
	str, err := base64.StdEncoding.DecodeString(strs[1])
	if err != nil {
		return err
	}
	logpass := strings.Split(string(str), ":")
	fmt.Println("api_srvtosmb: Ldap Dial: ", err)
	fmt.Println(fmt.Sprintf("%s:%d", s.pref.LdapServer, s.pref.LdapPort))
	l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", s.pref.LdapServer, s.pref.LdapPort))
	if err != nil {
		return err
	}
	defer l.Close()
	fmt.Println("api_srvtosmb: Ldap Ok: ", err)
	err = l.Bind(logpass[0]+"@"+s.pref.DomainName, logpass[1])
	if err != nil {
		fmt.Println("api_srvtosmb: Bind: ", err)
		fmt.Println("api_srvtosmb: s.pref.Template: ", s.pref.Template)
		return err
	}
	fmt.Println("api_srvtosmb: Bind Ok: ", err)
	searchRequest := ldap.NewSearchRequest(
		"OU=ATH,DC=ath,DC=ru",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(objectClass=person)(memberof:1.2.840.113556.1.4.1941:=CN=ftpadmin,OU=Services Accounts,OU=Moscow,OU=ATH,DC=ath,DC=ru)(|(sAMAccountName="+logpass[0]+")))"),
		[]string{"dn", "sAMAccountName", "mail"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Fatal(err)
		fmt.Println("api_srvtosmb: Search: ", err)
		header.Add("WWW-Authenticate", "Basic")
		return err
	}
	fmt.Println("api_srvtosmb: Search Ok: ", sr)
	for _, ent := range sr.Entries {
		if strings.EqualFold(ent.GetAttributeValue("sAMAccountName"), logpass[0]) {
			fmt.Println("api_srvtosmb: Search ent: ", ent.GetAttributeValue("sAMAccountName"))
			fmt.Println("api_srvtosmb: Search logpass: ", logpass[0])
			item := memcache.Item{}
			item.Key = StringWithCharset(20)
			item.Value = []byte(r.RemoteAddr)
			item.Expiration = 4 * 60 * 60
			s.client.Add(&item)
			var cookie http.Cookie
			cookie.Name = "ident"
			fmt.Println("api_srvtosmb: Search logpass: ", logpass[0])
			cookie.Value = string(item.Key)
			fmt.Println("api_srvtosmb: Search logpass: ", logpass[0])
			http.SetCookie(w, &cookie)
			fmt.Println("api_srvtosmb: Search logpass: ", logpass[0])
			return nil
		}
	}
	fmt.Println("api_srvtosmb: Authorization: ", string(str))
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

func (s *Server) PrintError(w *http.ResponseWriter, Error error, code int) {
	(*w).Header().Set("Content-Type", "application/xml")
	type Result struct {
		Success bool   `xml:"Success"`
		Error   string `xml:"Error"`
	}
	v := &Result{Success: false, Error: Error.Error()}
	encStdout := xml.NewEncoder(os.Stdout)
	encResponce := xml.NewEncoder(*w)
	encStdout.Indent("  ", "    ")
	encResponce.Indent("  ", "    ")
	if err := encStdout.Encode(v); err != nil {
		fmt.Printf("error: %v\n", err)
		(*w).Write([]byte(err.Error()))
		(*w).WriteHeader(500)
	}
	(*w).Write([]byte(xml.Header))
	if err := encResponce.Encode(v); err != nil {
		fmt.Printf("error: %v\n", err)
		(*w).Write([]byte(xml.Header + err.Error()))
		(*w).WriteHeader(500)
	}
}

func (s *Server) GetUserInfo(users []string, w http.ResponseWriter) {
	fmt.Println("main: api_err: GetUserInfo")
	for _, user := range users {
		rows, err := s.db.Query(fmt.Sprintf("select userid, uid from users where userid = '%s';", user))
		if err != nil {
			s.PrintError(&w, err, 404)
			return
		}
		defer rows.Close()
		next := rows.Next()
		for next {
			var userid string
			var uid int
			err := rows.Scan(&userid, &uid)
			fmt.Println("api_srvtosmb: rows err: ", err, " uid: ", uid)
			if err != nil {
				s.PrintError(&w, err, 500)
				return
			}
			type Result struct {
				Success bool `xml:"Success"`
				Locked  bool `xml:"Locked"`
			}
			v := Result{}
			fmt.Println("main: api_err: ", err)
			v.Success = true
			v.Locked = (uid == 65534)
			s.Answer(w, v)
			next = rows.Next()
			return
		}
		if next == false {
			s.PrintError(&w, errors.New("user not found"), 404)
		}
		if err := rows.Err(); err != nil {
			fmt.Println("main: api_err: ", err)
		}
	}

	return
}

func (s *Server) PostUserInfo(values url.Values, w http.ResponseWriter) {
	type Result struct {
		Success  bool   `xml:"Success"`
		Password string `xml:"Password"`
	}
	sqlt, err := s.db.Prepare("update users set passwd=? where userid=?;")
	defer sqlt.Close()
	if err != nil {
		fmt.Println("main: api_Prepare: ", err)
		s.PrintError(&w, err, 501)
		return
	}
	pass := StringWithCharset(10)
	if password, err := values["password"]; err {
		pass = password[0]
	}
	for _, val := range values["username"] {
		_, err := sqlt.Exec(pass, val)
		if err != nil {
			s.PrintError(&w, errors.New("password not update: "+err.Error()), 402)
			return
		}
	}
	v := Result{Success: true, Password: pass}
	s.Answer(w, v)
}

func (s *Server) Answer(w http.ResponseWriter, a ...interface{}) {
	encStdout := xml.NewEncoder(os.Stdout)
	encResponce := xml.NewEncoder(w)
	encStdout.Indent("  ", "    ")
	encResponce.Indent("  ", "    ")
	if err := encStdout.Encode(a); err != nil {
		s.PrintError(&w, err, 500)
	}
	w.Write([]byte(xml.Header))
	if err := encResponce.Encode(a); err != nil {
		s.PrintError(&w, err, 500)
	}
	w.WriteHeader(200)
}

func (s *Server) CreateUser(values url.Values, w http.ResponseWriter) {
	checkerr := func(err error) {
		if err != nil {
			fmt.Println("main: api_Prepare: ", err)
			s.PrintError(&w, err, 500)
			return
		}
	}
	type Result struct {
		Success  bool   `xml:"Success"`
		Password string `xml:"Password"`
	}
	v := Result{}
	sqltgrous, err := s.db.Prepare("INSERT INTO groups (groupname, gid, members) VALUES ('proftpd', 65534, ?);")
	checkerr(err)
	defer sqltgrous.Close()
	sqltusers, err :=
		s.db.Prepare("INSERT INTO users (userid, passwd, uid, gid, homedir, shell) VALUES (?, ?, 112, 65534, '/srv/smb/?/Incoming', '/usr/sbin/nologin');")
	checkerr(err)
	defer sqltusers.Close()
	pass := StringWithCharset(10)
	if password, err := values["password"]; err {
		pass = password[0]
	}
	username := values["username"][0]
	_, err = sqltgrous.Exec(username)
	checkerr(err)
	_, err = sqltusers.Exec(username, pass)
	checkerr(err)
	incomming := s.pref.PathHomeDir + username + "/Incoming"
	err = os.MkdirAll(incomming, 0700)
	checkerr(err)
	failed := s.pref.PathHomeDir + username + "/Failed"
	err = os.MkdirAll(failed, 0700)
	checkerr(err)
	processed := s.pref.PathHomeDir + username + "/Processed"
	err = os.MkdirAll(processed, 0700)
	checkerr(err)
	processing := s.pref.PathHomeDir + username + "/Processing"
	err = os.MkdirAll(processing, 0700)
	checkerr(err)
	err = os.Chown(incomming, 112, 65534)
	checkerr(err)
	err = os.Chown(failed, 112, 65534)
	checkerr(err)
	err = os.Chown(processed, 112, 65534)
	checkerr(err)
	err = os.Chown(processing, 112, 65534)
	checkerr(err)
	v.Success = true
	v.Password = pass
	s.Answer(w, v)
}

func (s *Server) LockUnlockUser(w http.ResponseWriter, username string, lock bool) {
	type Result struct {
		Success bool `xml:"Success"`
		Locked  bool `xml:"Locked"`
	}
	v := Result{}
	rows, err := s.db.Prepare("update users set uid=? where userid=?;")
	if err != nil {
		s.PrintError(&w, err, 404)
		return
	}
	defer rows.Close()
	if lock {
		_, err := rows.Exec(65534)
		if err != nil {
			s.PrintError(&w, err, 404)
			return
		}
	} else {
		_, err := rows.Exec(112)
		if err != nil {
			s.PrintError(&w, err, 404)
			return
		}
	}
	v.Success = true
	v.Locked = lock
	s.Answer(w, v)
}

func (s *Server) DeleteUser(w http.ResponseWriter, values url.Values) {
	checkerr := func(err error) {
		if err != nil {
			fmt.Println("main: api_Prepare: ", err)
			s.PrintError(&w, err, 500)
			return
		}
	}
	type Result struct {
		Success     bool     `xml:"Success"`
		UserDeleted []string `xml:"UserDeleted"`
	}
	v := Result{}
	v.Success = true
	sqltusers, err := s.db.Prepare("delete from users where userid=?;")
	checkerr(err)
	defer sqltusers.Close()
	sqltgroups, err := s.db.Prepare("delete from groups where members=?;")
	checkerr(err)
	defer sqltgroups.Close()
	for _, username := range values["username"] {
		_, err := sqltgroups.Exec(username)
		checkerr(err)
		_, err = sqltusers.Exec(username)
		checkerr(err)
		err = os.RemoveAll(s.pref.PathHomeDir + username)
		checkerr(err)
		v.UserDeleted = append(v.UserDeleted, username)
	}
	s.Answer(w, v)
}
