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
	"encoding/json"
	"github.com/sdidyk/mtproto"
	"strconv"
	"github.com/martinolsen/go-whois"
)

const (
	_DAEMON_NAME    = "agiserver"
	_DAEMON_DESC 	= "AGIServer"
	ipaddr 		= "127.0.0.1"
	port 		= "4573"
)

var (
	LOGPATH = "/var/log/asterisk/AGISERVER_log"
	ALLOW []string //ALLOW NETWORKS
	DENY []string //DENY NETWORKS
	stdlog, errlog *log.Logger
	TG []string
)

type Config struct {
	Network Network
	Tg Tg
}

type Network struct {
	Allow []string
	Deny []string
}

type Tg struct {
	Rcp []string
}

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
//	LoggerAGI(sess)
	startvar, err := sess.GetVariable("STARTVAR")
	if err == nil {
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

		if startvar.Dat == "block" {
			BanIpFromPSTN(b, sess)
		} else if startvar.Dat == "inbound" {
			InboundCall(sess)
		} else if startvar.Dat == "confbridge" {
			ConfBridge(sess)
		}
	}
	sess.Verbose("================== Complete ======================")
	sess.Verbose("STARTVAR IS " + startvar.Dat)
	return
}

func ConfBridge(sess *agi.Session) {

}

//test
func InboundCall(sess *agi.Session) {
	LoggerString("INCOMING NUM    " + sess.Env["callerid"])
	rex, err := regexp.Compile(`^[7|8](\d{10})$`)
	res := rex.FindStringSubmatch(sess.Env["callerid"])
	if res != nil {
		LoggerString("RES NOT NIL " + sess.Env["callerid"])
		_, err := sess.SetVariable("CALLERID(num)", res[1])
		if err != nil {
			LoggerErr(err)
		} else {
			LoggerString("NUM CHANGED TO  " + res[1])
		}
		_, err = sess.SetVariable("CALLERID(name)", res[1])
		if err != nil {
			LoggerErr(err)
		}
	} else {
//		LoggerString("NUM NOT CHANGED " + sess.Env["callerid"])
	}
	if err != nil {
		LoggerErr(err)
	}
	rex2, err := regexp.Compile(`^([a|A]nonymous|unknown)$`)
	res2 := rex2.FindStringSubmatch(sess.Env["calleridname"])
	if res2 != nil {
		LoggerString("RES2 " + res2[1])
		_, err := sess.SetVariable("CALLERID(name)", "0")
		if err != nil {
			LoggerErr(err)
		} else {
			LoggerString("NAME CHANGED TO 0")
		}
	}
	rex3, err := regexp.Compile(`^([a|A]nonymous|unknown)$`)
	res3 := rex3.FindStringSubmatch(sess.Env["callerid"])
	if res3 != nil {
		LoggerString("RES3 " + res3[1])
		_, err := sess.SetVariable("CALLERID(num)", "0")
		if err != nil {
			LoggerErr(err)
		} else {
			LoggerString("NUM CHANGED TO 0")
		}
	}

}

func BanIpFromPSTN(mm map[string]string, sess *agi.Session) {
	LoggerMap(mm)
	var BAN = make(map[string]string)
	rex, err := regexp.Compile(`^sip:(\S+)\@(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\:(\S+)$`)
	res := rex.FindStringSubmatch(mm["sipuri"])
	if res != nil {
		BAN["num"] = res[1]
		BAN["ip"] = res[2]
		BAN["port"] = res[3]
	}

	rex1, err := regexp.Compile(`^sip:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$`)
	res1 := rex1.FindStringSubmatch(mm["sipuri"])
	if res1 != nil {
		BAN["num"] = ""
		BAN["ip"] = res1[1]
		BAN["port"] = ""
	}

	rex2, err := regexp.Compile(`^sip:(\S+)\@(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$`)
	res2 := rex2.FindStringSubmatch(mm["sipuri"])
	if res2 != nil {
		BAN["num"] = res2[1]
		BAN["ip"] = res2[2]
		BAN["port"] = ""
	}
	LoggerMap(BAN)
	if err != nil {
		LoggerString("ERR")
	}
	checkIP(BAN["ip"])
}

//test
func checkIP(ipip string) {
//	NotifyTG("Phrickers Attack from " + ipip)
	anet := false;
	cip := net.ParseIP(ipip)
	for _, iprange := range ALLOW {
		ip, ipnet, err := net.ParseCIDR(iprange)
		if err != nil {
			LoggerErr(err)
		}
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
			if ip.String() == cip.String() {
				LoggerString("IP FROM ALLOW NETWORK " + ip.String())
				anet = true
				return
			}
		}
	}
	if !anet {
		whoisIP(ipip)
	}
}

//test
func inc(ip net.IP) {
	for j := len(ip)-1; j>=0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

//test
func whoisIP(ipip string) {
	w, err := whois.Lookup(ipip)
	var country string
	var inetnum string
	var route string
	if err != nil {
		LoggerErr(err)
	} else {
		if len(w.Get("country")) != 0 {
			LoggerString(w.Get("country"))
		} else {
			country = "Country NOT DEFINED"
			LoggerString(country)
		}
		if len(w.Get("inetnum")) != 0 {
			LoggerString(w.Get("inetnum"))
		} else {
			inetnum = "Inetnum NOT DEFINED"
			LoggerString(inetnum)
		}
		if len(w.Get("route")) != 0 {
			LoggerString(w.Get("route"))
		} else {
			route = "Route NOT DEFINED"
			LoggerString(route)
		}
	}
	NotifyTG("Phrickers Attack from " + ipip + " " + country + " " + inetnum + " " + route)
}

func NotifyTG(tg_msg string) {
	LoggerString(tg_msg)
//	m, err := mtproto.NewMTProto(os.Getenv("HOME") + "/.telegram_go")
	m, err := mtproto.NewMTProto("/root/.telegram_go")
	if err != nil {
		LoggerString("Create failed")
		LoggerErr(err)
	}
	err = m.Connect()
	if err != nil {
		LoggerString("Connect failed")
		LoggerErr(err)
	}
	for rcps, each := range TG {
		rcp := string(rcps)
		e := string(each)
		id, err := strconv.ParseInt(each, 10, 32)
		LoggerString("Send TG_MSG to " + e + " - " + rcp)
		err = m.SendMsg(int32(id), tg_msg)
		if (err != nil) {
			LoggerErr(err)
		}
	}
}

func init() {
	file, e1 := os.Open("/etc/asterisk/asterisk_config.json")
	if e1 != nil {
		fmt.Println("Error: ", e1)
	}
	decoder := json.NewDecoder(file)
	conf := Config{}
	err := decoder.Decode(&conf)
	if err != nil {
		fmt.Println("Error: ", err)
	}
	ALLOW = conf.Network.Allow
	DENY = conf.Network.Deny
	TG = conf.Tg.Rcp
	stdlog = log.New(os.Stdout, "", log.Ldate|log.Ltime)
	errlog = log.New(os.Stderr, "", log.Ldate|log.Ltime)
	NotifyTG("Start/Restart " + _DAEMON_NAME + " " + _DAEMON_DESC)
}

func main() {
	srv, err := daemon.New(_DAEMON_NAME, _DAEMON_DESC)
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

func LoggerErr(e error) {
	f, _ := os.OpenFile(LOGPATH, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	log.SetOutput(f)
	log.Print(e)
	fmt.Println(e)
}

func timeFormat() (string) {
	t := time.Now()
  	tf := fmt.Sprintf("%d-%02d-%02d %02d:%02d:%02d\n", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())
  	return tf
}
