package main

import (
	"os"
	"fmt"
	"log"
	"net"
	"time"
	"bufio"
	"regexp"
	"syscall"
	"strconv"
	"strings"
	"os/signal"
	"database/sql"
	"encoding/json"
	_ "github.com/lib/pq"
	"github.com/zaf/agi"
	"github.com/takama/daemon"
	"github.com/sdidyk/mtproto"
	"github.com/martinolsen/go-whois"
)

const (
	_DAEMON_NAME    = "agiserver"
	_DAEMON_DESC 	= "AGIServer"
	ipaddr 		= "127.0.0.1"
	port 		= "4573"
	_LT		= "\r\n" //"\x0D\x0A"
)

var (
	LOGPATH = "/var/log/asterisk/AGISERVER_log"
	ALLOW, DENY []string //ALLOW, DENY NETWORKS
	DBPass, DBName, DBHost, DBPort, DBUser, DBSSL string
	CONFBRIDGE_FEATURES string //CONFBRIDGE DYNAMIC FEATURES
	CONFBRIDGE_CONTEXT string //CONFBRIDGE CONTEXT
	CONFBRIDGE_ADD_CONTEXT string //CONFBRIDGE ADD USERS CONTEXT
	CONFBRIDGE_CONFS string //CONFBRIDGE CONTEXT FOR OTHER CHANNELS
	CONFBRIDGE_MEMBER_ADD string // CONFBRIDGE ADD USERS SOUND
	LEN_INNER_NUM, LEN_OUTER_NUM string // NUMBERS LENGTH
	OUTPEER string
	AMENU, UMENU string //CONFBRIDGE MENUS
	stdlog, errlog *log.Logger
	TG []string
	TGPATH string
	unquotedChar  = `[^",\\{}\s(NULL)]`
    	unquotedValue = fmt.Sprintf("(%s)+", unquotedChar)
    	quotedChar  = `[^"\\]|\\"|\\\\`
    	quotedValue = fmt.Sprintf("\"(%s)*\"", quotedChar)
	arrayValue = fmt.Sprintf("(?P<value>(%s|%s))", unquotedValue, quotedValue)
	arrayExp = regexp.MustCompile(fmt.Sprintf("((%s)(,)?)", arrayValue))
	CALLBACKSRC string
	CALLBACKDST string
	CALLBACKCONTEXT string
)

type Config struct {
	Tg Tg
	Pg Pg
	Network Network
	Confbridge Confbridge
	CallbackCall CallbackCall

}

type Tg struct {
	Rcp []string
	Path string
}

type Pg struct {
	DBPort string
	DBHost string
	DBUser string
	DBPass string
	DBName string
	DBSSL string
}

type Network struct {
	Allow []string
	Deny []string
}

type Confbridge struct {
	Df string
	Context string
	AdminMenu string
	UserMenu string
	AddMember string
	Conferences string
	PlayMemberAdd string
	LengthInnerNum string
	LengthOuterNum string
	OutPeer string
}

type CallbackCall struct {
	SrcDir string
	DstDir string
	Context string
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
		if startvar.Dat == "block" {
			BanIpFromPSTN(sess)
		} else if startvar.Dat == "inbound" {
			InboundCall(sess)
		} else if startvar.Dat == "confbridge_access" {
			ConfBridgeAccess(sess)
		} else if startvar.Dat == "confbridge_channelredirect" {
			ConfBridgeChannelRedirect(sess)
		} else if startvar.Dat == "confbridge_addmembers" {
			ConfBridgeAddMembers(sess)
		} else if startvar.Dat == "confbridge_confs" {
			ConfBridgeConfs(sess)
		}
	}
	sess.Verbose("================== Complete ======================")
	sess.Verbose("STARTVAR IS " + startvar.Dat)
	return
}

/*
func CallbackCall(sess *agi.Session, num string, name string, ) {
	src := CALLBACKSRC+num
	dst := CALLBACKDST+num
	f,
}
*/

//test 1
func ConfBridgeChannelRedirect(sess *agi.Session) {
	confno, err := sess.GetVariable("CONFNO")
	if err != nil {
		LoggerErr(err)
	}
	bridgepeer, err := sess.GetVariable("BRIDGEPEER")
	if err != nil {
		LoggerErr(err)
	}
	_, err = sess.Exec("ChannelRedirect", sess.Env["channel"] + "," + CONFBRIDGE_CONTEXT + "," + confno.Dat + ",1")
	if err != nil {
		LoggerErr(err)
	}
	_, err = sess.Exec("ChannelRedirect", bridgepeer.Dat + "," + CONFBRIDGE_CONTEXT + "," + confno.Dat + ",1")
	if err != nil {
		LoggerErr(err)
	}
	LoggerString("Try create Confbridge CONFNO " + confno.Dat + " Channel1 " + sess.Env["channel"] + " Channel2 " + bridgepeer.Dat)
}

//test 2
func ConfBridgeAccess(sess *agi.Session) {
	sess.Answer()
	_, err := sess.SetVariable("__CONFNO", sess.Env["extension"])
	if err != nil {
		LoggerErr(err)
	}
	_, err = sess.SetVariable("__DYNAMIC_FEATURES", CONFBRIDGE_FEATURES)
	if err != nil {
		LoggerErr(err)
	}
	if sess.Env["extension"] == sess.Env["callerid"] {
		inner_num, err := strconv.Atoi(LEN_INNER_NUM)
		if len(sess.Env["callerid"]) == inner_num {
			_, err = sess.Exec("ConfBridge", sess.Env["extension"] + ",,," + AMENU)
		} else {
			_, err = sess.Exec("ConfBridge", sess.Env["extension"] + ",,," + UMENU)
		}
		if err != nil {
			LoggerErr(err)
		}
	} else {
		_, err = sess.Exec("ConfBridge", sess.Env["extension"] + ",,," + UMENU)
	}
	if err != nil {
		LoggerErr(err)
	}
	LoggerString("Confbridge Admin " + sess.Env["extension"])
}

//test 3
func ConfBridgeAddMembers(sess *agi.Session) {
	_, err := sess.Exec("Read", "DST," + CONFBRIDGE_MEMBER_ADD + ",maxdigits,,2,12")
	if err != nil {
		LoggerErr(err)
	}
	dst, err := sess.GetVariable("DST")
	if err != nil {
		LoggerErr(err)
	} else {
		callerid := sess.Env["callerid"]
		_, err := sess.Exec("DumpChan", "255")
		if err != nil {
			LoggerErr(err)
		}
		inner_num, err := strconv.Atoi(LEN_INNER_NUM)
		outer_num, err := strconv.Atoi(LEN_OUTER_NUM)
		if len(dst.Dat) == inner_num {
			_, err = sess.Exec("Originate", "SIP/" + dst.Dat + ",exten," + CONFBRIDGE_CONFS + "," + callerid + ",1")
		} else if len(dst.Dat) == outer_num {
			_, err := sess.SetVariable("CALLERID(num)", OUTPEER)
			_, err = sess.Exec("Originate", "SIP/" + dst.Dat + "@" + OUTPEER + ",exten," + CONFBRIDGE_CONFS + "," + callerid + ",1")
			if err != nil {
				LoggerErr(err)
			}
		} else {
			LoggerString("NUM LENGTH NOT VALID")
		}
		if err != nil {
			LoggerErr(err)
		}
	}
	LoggerString("Confbridge Admin " + sess.Env["callerid"] + " try add " + dst.Dat)
}

//test 4
func ConfBridgeConfs(sess *agi.Session) {
	_, err := sess.Exec("DumpChan", "255")
	if err != nil {
		LoggerErr(err)
	}
	_, err = sess.SetVariable("__CONFNO", sess.Env["extension"])
	if err != nil {
		LoggerErr(err)
	}
	_, err = sess.Exec("ConfBridge", sess.Env["extension"] + ",,," + UMENU)
	if err != nil {
		LoggerErr(err)
	}
	LoggerString("Confbridge Admin add " + sess.Env["extension"])
}

//test
func InboundCall(sess *agi.Session) {
//	LoggerString("INCOMING NUM    " + sess.Env["callerid"])
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

func BanIpFromPSTN(sess *agi.Session) {
	useragent, err := sess.GetVariable("CHANNEL(useragent)")
	if err != nil {
		LoggerErr(err)
	} else {
		LoggerString("UserAgent " + useragent.Dat)
	}
	sipuri, err := sess.GetVariable("SIPURI")
	if err != nil {
		LoggerErr(err)
	} else {
		LoggerString("SIPURI " + sipuri.Dat)
	}
	var BAN = make(map[string]string)
	rex, err := regexp.Compile(`^sip:(\S+)\@(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\:(\S+)$`)
	res := rex.FindStringSubmatch(sipuri.Dat)
	if res != nil {
		BAN["num"] = res[1]
		BAN["ip"] = res[2]
		BAN["port"] = res[3]
	}
	rex1, err := regexp.Compile(`^sip:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$`)
	res1 := rex1.FindStringSubmatch(sipuri.Dat)
	if res1 != nil {
		BAN["num"] = ""
		BAN["ip"] = res1[1]
		BAN["port"] = ""
	}
	rex2, err := regexp.Compile(`^sip:(\S+)\@(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$`)
	res2 := rex2.FindStringSubmatch(sipuri.Dat)
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
//	anet := false;
	cip := net.ParseIP(ipip)
	for _, iprange := range ALLOW {
		ip, ipnet, err := net.ParseCIDR(iprange)
		if err != nil {
			LoggerErr(err)
		}
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
			if ip.String() == cip.String() {
				LoggerString("IP FROM ALLOW NETWORK " + ip.String())
//				anet = true
				return
			}
		}
	}
//	if anet == false {
		whoisIP(ipip)
//	}
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
	country := "NOT DEFINED"
	inetnum := "NOT DEFINED"
	route := "NOT DEFINED"
	w, err := whois.Lookup(ipip)
	if err != nil {
		LoggerErr(err)
	} else {
		if len(w.Get("country")) != 0 {
			LoggerString(w.Get("country"))
			country = w.Get("country")
		} else {
			LoggerString(country)
		}
		if len(w.Get("inetnum")) != 0 {
			LoggerString(w.Get("inetnum"))
			inetnum = w.Get("inetnum")
		} else {
			LoggerString(inetnum)
		}
		if len(w.Get("route")) != 0 {
			LoggerString(w.Get("route"))
			route = w.Get("route")
		} else if len(w.Get("cidr")) != 0 {
			LoggerString(w.Get("cidr"))
			route = w.Get("cidr")
		} else {
			route = "NO ROUTE OR CIDR FIELD"
		}
	}
	NotifyTG("Phreackers Attack: " + ipip + _LT + "Country: " + country + _LT + "Inetnum: " + inetnum + _LT + "Route: " + route)
}



func NotifyTG(tg_msg string) {
	LoggerString(tg_msg)
	m, err := mtproto.NewMTProto(TGPATH)
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

func sqlPut(query string) {
	dbinfo := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		DBHost, DBPort, DBUser, DBPass, DBName, DBSSL)
	db, err := sql.Open("postgres", dbinfo)
	if (err != nil) {
		fmt.Println(err)
	}
	result, err := db.Exec(query)
	if err != nil {
		LoggerErr(err)
	}
	result.LastInsertId()
	db.Close()
}

func sqlGetArray(query string) []string {
	dbinfo := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		DBHost, DBPort, DBUser, DBPass, DBName, DBSSL)
	db, err := sql.Open("postgres", dbinfo)
	if (err != nil) {
		LoggerErr(err)
	}
	rows, err := db.Query(query)
	if (err != nil) {
		LoggerErr(err)
	} else {

	}
	defer rows.Close()

	var arr string
	var el []string
	for rows.Next() {
		rows.Scan(&arr)
		VAR := pgArrayToSlice(arr)
		el = append(el, VAR...)
	}
	if (len(el) < 1) {
		el = append(el, "Err")
	}
	db.Close()
	return el
}

func pgArrayToSlice(array string) []string {
    var valueIndex int
    results := make([]string, 0)
    matches := arrayExp.FindAllStringSubmatch(array, -1)
    for _, match := range matches {
        s := match[valueIndex]
        s = strings.Trim(s, "\"")
        results = append(results, s)
    }
    return results
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
	CONFBRIDGE_FEATURES = conf.Confbridge.Df
	CONFBRIDGE_CONTEXT = conf.Confbridge.Context
	CONFBRIDGE_ADD_CONTEXT = conf.Confbridge.AddMember
	CONFBRIDGE_CONFS = conf.Confbridge.Conferences
	CONFBRIDGE_MEMBER_ADD = conf.Confbridge.PlayMemberAdd
	LEN_INNER_NUM = conf.Confbridge.LengthInnerNum
	LEN_OUTER_NUM = conf.Confbridge.LengthOuterNum
	OUTPEER = conf.Confbridge.OutPeer
	TG = conf.Tg.Rcp
	TGPATH = conf.Tg.Path
	AMENU = conf.Confbridge.AdminMenu
	UMENU = conf.Confbridge.UserMenu

	DBPass = conf.Pg.DBPass
	DBName = conf.Pg.DBName
	DBHost = conf.Pg.DBHost
	DBPort = conf.Pg.DBPort
	DBUser = conf.Pg.DBUser
	DBSSL = conf.Pg.DBSSL

	CALLBACKSRC = conf.CallbackCall.SrcDir
	CALLBACKDST = conf.CallbackCall.DstDir
	CALLBACKCONTEXT = conf.CallbackCall.Context

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
