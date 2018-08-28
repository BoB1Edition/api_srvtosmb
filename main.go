package main

import (
	"Preferences"
	"Server"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/takama/daemon"
)

// Service has embedded daemon
type Service struct {
	daemon.Daemon
}

func (service *Service) Manage() (string, error) {
	errlog := log.New(os.Stderr, "api_smbtoftp", 0)
	pref := Preferences.Preference{}
	if err := pref.LoadPreference("/etc/api_srvtosmb/config.json"); err != nil {
		errlog.Println("Error: loading preference", err)
		os.Exit(1)
	}
	usage := "Usage: myservice install | remove | start | stop | status"
	// if received any kind of command, do it
	if len(os.Args) > 1 {
		command := os.Args[1]
		switch command {
		case "install":
			return service.Install()
		case "remove":
			return service.Remove()
		case "start":
			//go Start()
			return service.Start()
		case "stop":
			return service.Stop()
		case "status":
			return service.Status()
		case "reload":
			return service.Reload(&pref)
		default:
			return usage, nil
		}
	}
	errlog.Println("start")
	go Start(&pref)

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, os.Kill, syscall.SIGTERM)
	for {
		fmt.Println("For")
		select {
		case killSignal := <-interrupt:
			errlog.Println("Got signal:", killSignal)
			errlog.Println("Stoping listening on ")
			//listener.Close()
			if killSignal == os.Interrupt {
				return "Daemon was interrupted by system signal", nil
			}
		}
	}
	return usage, nil
}

func Start(pref *Preferences.Preference) {
	fmt.Println("Start")
	errlog := log.New(os.Stderr, "api_smbtoftp", 0)
	fmt.Println(pref)
	serv := Server.Server{}
	serv.LoadPref(pref)
	http.HandleFunc("/", serv.Server)
	err := http.ListenAndServe((pref.Address + ":" + strconv.Itoa(pref.Port)), nil)
	if err != nil {
		errlog.Println("Error: server not start", err)
		os.Exit(1)
	}
	fmt.Println("exit")
}

func main() {
	errlog := log.New(os.Stderr, "api_smbtoftp", 0)
	//errlog
	var dependencies = []string{"nginx.service", "memcached.service"}
	srv, err := daemon.New("api_smbtoftp", "my first go demon", dependencies...)
	if err != nil {
		errlog.Println("Error: ", err)
		os.Exit(1)
	}
	service := &Service{srv}
	status, err := service.Manage()
	if err != nil {
		errlog.Println(status, "\nError: ", err)
		os.Exit(1)
	}
	fmt.Println("status: ", status)
}

func (s *Service) Reload(pref *Preferences.Preference) (string, error) {
	if err := pref.LoadPreference("/etc/api_srvtosmb/config.json"); err != nil {
		fmt.Println("Error reloading: loading preference", err)
		os.Exit(1)
		return "", err
	}
	return "Service Reload: ", nil
}
