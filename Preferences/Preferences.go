package Preferences

import (
	"encoding/json"
	"io/ioutil"
)

type Preference struct {
	Port            int
	Address         string
	UserMySql       string
	PasswordMySql   string
	DatabaseMySql   string
	Template        string
	MemcachedServer string
	MemcachedPort   int
	LdapServer      string
	LdapPort        int
	DomainName      string
}

func (pref *Preference) LoadPreference(fname string) error {
	file, err := ioutil.ReadFile(fname)
	if err != nil {
		return err
	}
	err = json.Unmarshal(file, pref)
	return err
}
