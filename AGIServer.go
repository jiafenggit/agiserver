package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"bufio"
	"github.com/takama/daemon"
	"github.com/zaf/agi"
	"time"
	"regexp"
)

const (
	name        = "agiserver"
	description = "AGIServer"
	ipaddr 		= "127.0.0.1"
	port 		= "4573"
)

var LOGPATH = "/var/log/asterisk/AGISERVER_log"
var stdlog, errlog *log.Logger

type Service struct {
	daemon.Daemon
}

func (service *Service) Manage() (string, error) {
	usage := "Usage: myservice install | remove | start | stop | status"
	if len(os.Args) > 1 {
		command := os.Args[1]
		switch command {
		case "install":
			return service.Install()
		case "remove":
			return service.Remove()
		case "start":
			return service.Start()
		case "stop":
			return service.Stop()
		case "status":
			return service.Status()
		default:
			return usage, nil
		}
	}

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, os.Kill, syscall.SIGTERM)

	astEnv := getAstEnv()
	if astEnv["AST_AGI_DIR"] != "" {
		// Started as a standalone AGI app by asterisk.
		spawnAgi(nil)
	} else {
		ln, err := net.Listen("tcp", ipaddr + ":" + port)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Listening for FastAGI connections on " + ipaddr + ":" + port)
		defer ln.Close()
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Println(err)
				continue
			}
			go spawnAgi(conn)
		}
	}
	return usage, nil
}

func getAstEnv() map[string]string {
	var env = map[string]string{
		"AST_CONFIG_DIR":  os.Getenv("AST_CONFIG_DIR"),
		"AST_CONFIG_FILE": os.Getenv("AST_CONFIG_FILE"),
		"AST_MODULE_DIR":  os.Getenv("AST_MODULE_DIR"),
		"AST_SPOOL_DIR":   os.Getenv("AST_SPOOL_DIR"),
		"AST_MONITOR_DIR": os.Getenv("AST_MONITOR_DIR"),
		"AST_VAR_DIR":     os.Getenv("AST_VAR_DIR"),
		"AST_DATA_DIR":    os.Getenv("AST_DATA_DIR"),
		"AST_LOG_DIR":     os.Getenv("AST_LOG_DIR"),
		"AST_AGI_DIR":     os.Getenv("AST_AGI_DIR"),
		"AST_KEY_DIR":     os.Getenv("AST_KEY_DIR"),
		"AST_RUN_DIR":     os.Getenv("AST_RUN_DIR"),
	}
	return env
}

// Start the AGI or FastAGI session.
func spawnAgi(c net.Conn) {
	myAgi := agi.New()
	var err error
	if c != nil {
		// Create a new FastAGI session.
		rw := bufio.NewReadWriter(bufio.NewReader(c), bufio.NewWriter(c))
		err = myAgi.Init(rw)
		defer c.Close()
	} else {
		// Create a new AGI session.
		err = myAgi.Init(nil)
	}
	if err != nil {
		log.Printf("Error Parsing AGI environment: %v\n", err)
		return
	}
	agiSess(myAgi)
	return
}

func agiSess(sess *agi.Session) {
	var err error
	LoggerAGI(sess)
	startvar, err := sess.GetVariable("STARTVAR")
	if err == nil {
		if startvar.Dat == "block" {
			var b = make(map[string]string)
			useragent, err := sess.GetVariable("CHANNEL(useragent)")
			if err == nil {
				b["useragent"] = useragent.Dat
			}
			sipuri, err := sess.GetVariable("SIPURI")
			if err == nil {
				b["sipuri"] = sipuri.Dat
			}
			sipdomain, err := sess.GetVariable("SIPDOMAIN")
			if err == nil {
				b["sipdomain"] = sipdomain.Dat
			}
			b["dnid"] = sess.Env["dnid"]
			b["extension"] = sess.Env["extension"]
			b["calleridname"] = sess.Env["calleridname"]
			BanIpFromPSTN(b)
		}
	}
	sess.Verbose("================== Complete ======================")
	return
}

func BanIpFromPSTN(mm map[string]string) {
	LoggerMap(mm)
	rex, err := regexp.Compile(`^sip:(\S+)\@(\S+)\:(\S+)$`)
	res := rex.FindStringSubmatch(mm["sipuri"])
	for v, k := range res {
		kk := string(k)
		vv := string(v)
		LoggerString(kk + " - " + vv)
	}
	rex1, err := regexp.Compile(`^sip:(\d+)\.(\d+)\.(\d+)\.(\d+)$`)
	res1 := rex1.FindStringSubmatch(mm["sipuri"])
	for v1, k1 := range res1 {
		kk1 := string(k1)
		vv1 := string(v1)
		LoggerString(kk1 + " - " + vv1)
	}
	rex2, err := regexp.Compile(`^sip:(\S+)@(\d+)\.(\d+)\.(\d+)\.(\d+)$`)
	res2 := rex2.FindStringSubmatch(mm["sipuri"])
	for v2, k2 := range res2 {
		kk2 := string(k2)
		vv2 := string(v2)
		LoggerString(kk2 + " - " + vv2)
	}


	if err != nil {

	}

}

func init() {
	stdlog = log.New(os.Stdout, "", log.Ldate|log.Ltime)
	errlog = log.New(os.Stderr, "", log.Ldate|log.Ltime)
}

func main() {
	srv, err := daemon.New(name, description)
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
	fmt.Println(status)
}

//DEBUG

func LoggerMap(s map[string]string) {
  	tf := timeFormat()
	f, _ := os.OpenFile(LOGPATH, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
 	log.SetOutput(f)
  	log.Print(tf)
  	log.Print(s)
  	fmt.Println(s)
}

func LoggerString(s string) {
	tf := timeFormat()
	f, _ := os.OpenFile(LOGPATH, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	log.SetOutput(f)
	log.Print(tf)
	log.Print(s)
	fmt.Println(s)
}

func LoggerAGI(s *agi.Session) {
	tf := timeFormat()
	f, _ := os.OpenFile(LOGPATH, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	log.SetOutput(f)
	log.Print(tf)
	log.Print(s)
	fmt.Println(s)
}

func LoggerAGIReply(s agi.Reply) {
	tf := timeFormat()
	f, _ := os.OpenFile(LOGPATH, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	log.SetOutput(f)
	log.Print(tf)
	log.Print(s)
	fmt.Println(s)
}

func LoggerMapMap(m map[string][]map[string]string) {
	f, _ := os.OpenFile(LOGPATH, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	log.SetOutput(f)
	log.Print(m)
	fmt.Println(m)
}

func timeFormat() (string) {
	t := time.Now()
  	tf := fmt.Sprintf("%d-%02d-%02d %02d:%02d:%02d\n", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())
  	return tf
}