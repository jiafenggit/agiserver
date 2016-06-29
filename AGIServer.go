package main

import (
	"os"
	"fmt"
	"log"
	"net"
	"time"
	"bytes"
	"bufio"
	"regexp"
	"syscall"
	"strconv"
	"strings"
	"net/smtp"
	"os/signal"
	"crypto/md5"
	"crypto/aes"
	"database/sql"
	"encoding/hex"
	"crypto/cipher"
	"encoding/json"
	"github.com/zaf/agi"
	_ "github.com/lib/pq"
	"github.com/takama/daemon"
	"github.com/yosh0/mtproto"
	"github.com/martinolsen/go-whois"
)

const (
	_DN 		= "agiserver"
	_DD	 	= "AGIServer"
	_LT		= "\x0D\x0A"
	_KVT 		= ":"
)

var (
	LOGPATH = ""
	ALLOW, DENY []string //ALLOW, DENY NETWORKS
	DBPass, DBName, DBHost, DBPort, DBUser, DBSSL string
	CONFBRIDGE_FEATURES string //CONFBRIDGE DYNAMIC FEATURES
	CONFBRIDGE_CONTEXT string //CONFBRIDGE CONTEXT
	CONFBRIDGE_ADD_CONTEXT string //CONFBRIDGE ADD USERS CONTEXT
	CONFBRIDGE_CONFS string //CONFBRIDGE CONTEXT FOR OTHER CHANNELS
	CONFBRIDGE_MEMBER_ADD string // CONFBRIDGE ADD USERS SOUND
	LEN_INNER_NUM, LEN_OUTER_NUM string // NUMBERS LENGTH
	CONFBRIDGES = make(map[string][]map[string]string) // CONNECTED CONFBRIDGES
	MAILSERVER, MAILPORT, MAILDOMAIN, MAILTO, MAIL, MAILHEADER string
	BALDIR, BALDDIR, BALANCE, BALCONTRACT, BALNOMONEY, BALONCONRACT, BALMINUS, BALRICH, BALRUB, BALKOP string
	FAXDIR, FAXRECVSTR string
	FAXNUMS []string
	OUTPEER string
	AGIHOST, AGIPORT string
	AMIhost, AMIuser, AMIpass, AMIport string
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
	CALLBACKDST, CALLBACKQUERY, CALLBACKSET, CALLBACKCONFBRIDGE string
	BLOCKPSTNQUERY string
	UEBLOCKEDABON string
	AGI2AMI, AGI2AMICONFBRIDGE string
)

type Config struct {
	Tg Tg
	Pg Pg
	Ami Ami
	Fax Fax
	Mail Mail
	LogDir LogDir
	Balance Balance
	Network Network
	Callback Callback
	AgiServer AgiServer
	Confbridge Confbridge
	UserEvents UserEvents
	BlockFromPSTN BlockFromPSTN
}

type Ami struct {
	RemotePort string
	RemoteHost string
	Username   string
	Password   string
}

type LogDir struct {
	Path string
}

type Balance struct {
	Dir 		string
	DDir 		string
	Balance 	string
	Contract 	string
	FNoMoney 	string
	FOnContract 	string
	FMinus 		string
	FRich 		string
	Rub 		string
	Kop 		string
}

type UserEvents struct {
	BlockedAbon 		string
	AGI2AMI 		string
	AGI2AMIConfBridge	string
}

type BlockFromPSTN struct {
	Query string
}

type Tg struct {
	Rcp 	[]string
	Path 	string
}

type Pg struct {
	DBPort 	string
	DBHost 	string
	DBUser 	string
	DBPass 	string
	DBName 	string
	DBSSL 	string
}

type Mail struct {
	Server	string
	Port	string
	Domain	string
	Mailto	string
	Mail 	string
	Header 	string
}

type Fax struct {
	Dir 	string
	RecvStr string
	Nums 	[]string
}

type Network struct {
	Allow 	[]string
	Deny 	[]string
}

type AgiServer struct {
	Host 	string
	Port 	string
}

type Confbridge struct {
	Df 		string
	OutPeer 	string
	Context 	string
	AdminMenu 	string
	UserMenu 	string
	AddMember 	string
	Conferences 	string
	PlayMemberAdd 	string
	LengthInnerNum 	string
	LengthOuterNum 	string
}

type Callback struct {
	DstDir 	string
	Query 	string
	Set 	string
	SetConfbridge string
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
		spawnAgi(nil)
	} else {
		ln, err := net.Listen("tcp", fmt.Sprintf("%s:%s", AGIHOST, AGIPORT))
		if err != nil {
			log.Fatal(err)
		}
		log.Printf(fmt.Sprintf("Listening for FastAGI connections on %s:%s", AGIHOST, AGIPORT))
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
	startvar, err := sess.GetVariable("STARTVAR")
	if err == nil {
		switch startvar.Dat {
		case "inbound" :
			InboundCall(sess)
		case "block" :
			BanIpFromPSTN(sess)
		case "confbridge_access" :
			ConfBridgeAccess(sess)
		case "confbridge_channelredirect" :
			ConfBridgeChannelRedirect(sess)
		case "confbridge_addmembers" :
			ConfBridgeAddMembers(sess)
		case "confbridge_confs" :
			ConfBridgeConfs(sess)
		case "callback_call" :
//			CallbackCall(sess)
			CallbackCheck(sess)
		case "fax_receive" :
			FaxRecv(sess)
		case "blocked_from_pstn" :
			BlockedFromPSTN(sess)
		case "balance" :
			BalanceInfo(sess)
		default:
			sess.Verbose("DEFAULT STARTVAR")
		}
	}
	sess.Verbose("================== Complete ======================")
	sess.Verbose("STARTVAR IS " + startvar.Dat)
	return
}

func BalanceInfo(sess *agi.Session) {
	b, err := sess.GetVariable(BALANCE)
	if err != nil {
		LoggerErr(err)
	} else {
		LoggerString(b.Dat)
	}
	c, err := sess.GetVariable(BALCONTRACT)
	if err != nil {
		LoggerErr(err)
	}
	sess.Verbose(fmt.Sprintf("BALANCE: %s %s %s", b.Dat, c.Dat, sess.Env["callerid"]))
	LoggerString(fmt.Sprintf("BALANCE: %s %s %s", b.Dat, c.Dat, sess.Env["callerid"]))
	bi, err := strconv.Atoi(b.Dat)
	sess.Verbose("BALANCE TO INT")
	bif, err := strconv.ParseFloat(b.Dat, 64)
	sess.Verbose(bi)
	sess.Verbose(bif)
	FILES := make([]string, 0)
	if bif < 0 {
		sess.Verbose("< 0")
		FILES = []string{BALNOMONEY, BALONCONRACT, BALMINUS}
		eBackground(sess, BALDIR, FILES)
	} else if bif > 0 && bif < 500 {
		sess.Verbose("0 > < 500")
		FILES = []string{BALONCONRACT}
		eBackground(sess, BALDIR, FILES)
	} else if bif > 500 {
		sess.Verbose("> 500")
		FILES = []string{BALRICH, BALONCONRACT}
		eBackground(sess, BALDIR, FILES)
	} else {
		sess.Verbose("ELSE")
		FILES = []string{BALONCONRACT}
		eBackground(sess, BALDIR, FILES)
	}
	bii := strconv.FormatFloat(bif, 'g', 10, 64)
	rex, err := regexp.Compile(`^(\d+)\.(\d{2})\d*$`)
	res := rex.FindStringSubmatch(bii)
	if res != nil {
		sess.Verbose(res[1]+ " " + res[2])
		rub := res[1]
		kop := res[2]
		rex2, err := regexp.Compile(`^0(\d+)$`)
		res2 := rex2.FindStringSubmatch(kop)
		if res2 != nil {
			kop = res2[1]
		}
		if err != nil {
			LoggerErr(err)
		}
		BalanceDigits(sess, BALRUB, rub)
		BalanceDigits(sess, BALKOP, kop)
	}
	rex3, err := regexp.Compile(`^(\d+)\.(\d{1})$`)
	res3 := rex3.FindStringSubmatch(bii)
	if res3 != nil {
		sess.Verbose(res3[1]+ " " + res3[2])
		rub := res3[1]
		kop := res3[2]
		BalanceDigits(sess, BALRUB, rub)
		BalanceDigits(sess, BALKOP, kop)
	}
	rex4, err := regexp.Compile(`^(\d+)$`)
	res4 := rex4.FindStringSubmatch(bii)
	if res4 != nil {
		sess.Verbose(res4[1])
		rub := res4[1]
		if rub == "0" {
			FILES = []string{"0", BALRUB+"-i", "0", BALKOP+"-k"}
			eBackground(sess, BALDDIR, FILES)
		} else {
			BalanceDigits(sess, BALRUB, rub)
		}
	}
	rex5, err := regexp.Compile(`^\-(\d+)\.(\d{2})\d*$`)
	res5 := rex5.FindStringSubmatch(bii)
	if res5 != nil {
		sess.Verbose(res5[1]+ " " + res5[2])
		rub := res5[1]
		kop := res5[2]
		rex55, err := regexp.Compile(`^0(\d+)$`)
		res55 := rex55.FindStringSubmatch(kop)
		if res55 != nil {
			kop = res55[1]
		}
		if err != nil {
			LoggerErr(err)
		}
		BalanceDigits(sess, BALRUB, rub)
		BalanceDigits(sess, BALKOP, kop)
	}
	rex6, err := regexp.Compile(`^\-(\d+)$`)
	res6 := rex6.FindStringSubmatch(bii)
	if res6 != nil {
		sess.Verbose(res6[1])
		rub := res6[1]
		if rub == "0" {
			FILES = []string{"0", BALRUB+"-i", "0", BALKOP+"-k"}
			eBackground(sess, BALDDIR, FILES)
		} else {
			BalanceDigits(sess, BALRUB, rub)
		}
	}

}

func eBackground(sess *agi.Session, dir string, phrases []string) {
	for _, phrase := range phrases {
		sess.Verbose("Phrase: "+phrase)
		_, err:= sess.Exec("Background", fmt.Sprintf("%s%s", dir, phrase))
		if err != nil {
			LoggerErr(err)
		}
	}
}

func BalanceDigits(sess *agi.Session, class string, dd string) {
	d, err := strconv.Atoi(dd)
	if err != nil {
		LoggerErr(err)
	}
	var unity, tens, hundreds, thousand int
	if d >= 1000 && d < 1000000 {
		thousand = d/1000
		if class != "thousand" {
			t := strconv.Itoa(thousand)
			BalanceDigits(sess, "thousand", t)
		}
		hundreds = ((d - thousand*1000)/100)*100
		if hundreds < 1 {
			hundreds = 0
		}
		tens = d - thousand * 1000 - hundreds
		if tens >= 10 && tens < 20 {
			unity = 0
		} else {
			tens = (tens/10)*10
			unity = (d - thousand * 1000 - hundreds - tens)
		}
		if tens < 10 {
			tens = 0
		}
		if hundreds != 0 {
			h := strconv.Itoa(hundreds)
			eBackground(sess, BALDDIR, []string{h})
		}
		if tens != 0 {
			t := strconv.Itoa(tens)
			eBackground(sess, BALDDIR, []string{t})
		}
		if unity != 0 {
			BalanceDigitsUnity(sess, class, unity)
		}
		BalanceMoney(sess, class, unity)
	} else if d >= 100 && d < 1000 {
		hundreds = (d/100)*100
		if (d - hundreds) < 10 {
			tens = 0
			unity = d - hundreds
		} else if (d - hundreds) > 10 && (d - hundreds) < 20 {
			tens = d - hundreds
		} else {
			tens = ((d - hundreds)/10)*10
			unity = d - hundreds - tens
		}
		h:= strconv.Itoa(hundreds)
		eBackground(sess, BALDDIR, []string{h})
		if tens != 0 {
			t := strconv.Itoa(tens)
			eBackground(sess, BALDDIR, []string{t})
		}
		if unity != 0 {
			BalanceDigitsUnity(sess, class, unity)
		}
		BalanceMoney(sess, class, unity)
	} else if d >= 10 && d < 100 {
		if d < 20 {
			tens = d
			unity = 0
		} else {
			tens = (d/10)*10
			unity = d - tens
		}
		t := strconv.Itoa(tens)
		eBackground(sess, BALDDIR, []string{t})
		if unity != 0 {
			BalanceDigitsUnity(sess, class, unity)
		}
		BalanceMoney(sess, class, unity)
	} else if d >= 1 && d < 10 {
		BalanceDigitsUnity(sess, class, d)
		BalanceMoney(sess, class, d)
	}
}

func BalanceDigitsUnity(sess *agi.Session, class string, d int) {
	if d > 2 || class == BALRUB {
		ds := strconv.Itoa(d)
		eBackground(sess, BALDDIR, []string{ds})
	}
	if (d == 2 && class == BALKOP) || (d == 2 && class == "thousand") {
		ds := strconv.Itoa(d)
		eBackground(sess, BALDDIR, []string{ds+"_e"})
	}
}

func BalanceMoney(sess *agi.Session, class string, d int) {
	if class == BALRUB {
		if d == 1 {
			eBackground(sess, BALDDIR, []string{BALRUB})
		}
		if d > 1 && d <= 4 {
			eBackground(sess, BALDDIR, []string{BALRUB+"-ja"})
		}
		if (d > 4 && d <= 9) || d == 0 {
			eBackground(sess, BALDDIR, []string{BALRUB+"-i"})
		}
	} else if class == BALKOP {
		if d == 1 {
			eBackground(sess, BALDDIR, []string{"1-a_kopeika"})
		}
		if d > 1 && d <= 4 {
			eBackground(sess, BALDDIR, []string{BALKOP+"-i"})
		}
		if (d > 4 && d <= 9) || d == 0 {
			eBackground(sess, BALDDIR, []string{BALKOP+"-k"})
		}
	} else if class == "thousand" {
		if d == 1 {
			eBackground(sess, BALDDIR, []string{"1000"})
		} else if d >= 5 || d == 0 {
			eBackground(sess, BALDDIR, []string{"1000_ch"})
		} else {
			eBackground(sess, BALDDIR, []string{"1000_i"})
		}
	}
}

func BlockedFromPSTN(sess *agi.Session) {
	dbinfo := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		DBHost, DBPort, DBUser, DBPass, DBName, DBSSL)
	db, err := sql.Open("postgres", dbinfo)
	if (err != nil) {
		LoggerErr(err)
	}
	rows, err := db.Query(fmt.Sprintf(BLOCKPSTNQUERY, sess.Env["callerid"]))
	if err != nil {
		LoggerErr(err)
	}
	defer rows.Close()
	var arg1, arg2 string
	for rows.Next() {
		rows.Scan(&arg1, &arg2)
	}
	db.Close()
	if len(arg1) != 0 && len(arg2) != 0 {
		_, err := sess.Exec("UserEvent", fmt.Sprintf(UEBLOCKEDABON, sess.Env["callerid"], sess.Env["uniqueid"]))
		if err != nil {
			LoggerErr(err)
		}
		sess.Hangup()
	}
}

func isValueInList(value string, list []string) bool {
    	for _, v := range list {
        	if v == value {
            		return true
        	}
    	}
    	return false
}

func FaxRecv(sess *agi.Session) {
	sess.Answer()
	uid := strings.Split(sess.Env["uniqueid"], ".")
	_, err := sess.SetVariable("FAXFILENAME", fmt.Sprintf("%s_%s_%s", sess.Env["callerid"], sess.Env["dnid"], uid[0]))
	_, err = sess.SetVariable("FAXOPT(headerinfo)", fmt.Sprintf("Received_by_%s_%s", sess.Env["callerid"], uid[0]))
	_, err = sess.SetVariable("FAXOPT(localstationid)", sess.Env["callerid"])
	_, err = sess.SetVariable("FAXOPT(maxrate)", "14400")
	_, err = sess.SetVariable("FAXOPT(minrate)", "4800")
	filename, err := sess.GetVariable("FAXFILENAME")
	_, err = sess.Exec("ReceiveFax", fmt.Sprintf(FAXDIR+FAXRECVSTR, filename.Dat))
	if err != nil {
		LoggerErr(err)
	} else {
		fs, err := sess.GetVariable("FAXSTATUS")
		fp, err := sess.GetVariable("FAXPAGES")
		fb, err := sess.GetVariable("FAXBITRATE")
		fr, err := sess.GetVariable("FAXRESOLUTION")
		if err != nil {
			LoggerErr(err)
		}
		if fs.Dat == "" || fs.Dat == "FAILED" {
			fs.Dat = "FAILED"
		}
		msg := fmt.Sprintf("Статус: %s\nС номера: %s\nНа номер: %s\nКоличество страниц: %s\nСкорость передачи(bitrate): %s\nРазрешение файла: %s",
			fs.Dat, sess.Env["callerid"], sess.Env["dnid"], fp.Dat, fb.Dat, fr.Dat)
		NotifyMail("ФаксВходящий", sess.Env["callerid"], msg, MAIL)
		NotifyMail("ФаксВходящий", sess.Env["callerid"], msg, "fax-"+sess.Env["dnid"])
//		NotifyTG(msg)
	}
	sess.Hangup()
}

func CallbackCheck(sess *agi.Session) {
	dbinfo := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		DBHost, DBPort, DBUser, DBPass, DBName, DBSSL)
	db, err := sql.Open("postgres", dbinfo)
	if (err != nil) {
		LoggerErr(err)
	}
	rows, err := db.Query(fmt.Sprintf(CALLBACKQUERY, sess.Env["callerid"]))
	if err != nil {
		LoggerErr(err)
	}
	defer rows.Close()
	var arg1, arg2, arg3, arg4, arg5 string
	for rows.Next() {
		rows.Scan(&arg1, &arg2, &arg3, &arg4, &arg5)
	}
	db.Close()
	if len(arg1) != 0 && len(arg2) != 0 && len(arg3) != 0 && len(arg4) != 0 {
		CallbackCall(sess, arg1, arg2, arg3, arg4, true)
	}
}

func CallbackCall(sess *agi.Session, arg1 string, arg2 string, arg3 string, arg4 string, earg bool) {
	buf := bytes.NewBufferString("")
	var call string
	var dst string
	if earg == true {
		call = fmt.Sprintf(CALLBACKSET, arg3, arg2, arg1, arg1, arg1, arg2, arg3, arg4, "0", "0", "FALSE")
		dst = CALLBACKDST + sess.Env["callerid"]
	} else {
		call = fmt.Sprintf(CALLBACKCONFBRIDGE, arg1, arg1, arg1)
		dst = CALLBACKDST + arg1
	}
	buf.Write([]byte(call))
	f, _ := os.OpenFile(dst, os.O_WRONLY | os.O_CREATE | os.O_APPEND, 0666)
	f.Write(buf.Bytes())
	defer f.Close()
	err := os.Chmod(dst, 0777)
	if err != nil {
		LoggerErr(err)
	}
}

func RedirectChan(mm map[string]string) {
	LoggerMap(mm)
	var r = make(map[string]string)
	r["Action"] = "BlindTransfer"
	r["Channel"] = mm["Channel"]
	r["Exten"] = mm["Exten"]
	r["Context"] = mm["Context"]
	amiAction(r)
}

//test 1
func ConfBridgeChannelRedirect(sess *agi.Session) {
	confno, err := sess.GetVariable("CONFNO")
	if err != nil {
		LoggerErr(err)
	} else {
		if confno.Dat == sess.Env["callerid"] {
			bridgepeer, err := sess.GetVariable("BRIDGEPEER")
			if err != nil {
				LoggerErr(err)
			}
			var rc1 = make(map[string]string)
			rc1["Channel"] = sess.Env["channel"]
			rc1["Exten"] = confno.Dat
			rc1["Context"] = CONFBRIDGE_CONTEXT
			var rc2 = make(map[string]string)
			rc2["Channel"] = bridgepeer.Dat
			rc2["Exten"] = confno.Dat
			rc2["Context"] = CONFBRIDGE_CONTEXT
			ConfBridgeSettings(sess)
			RedirectChan(rc1)
			RedirectChan(rc2)
			LoggerString(fmt.Sprintf("Try create Confbridge CONFNO %s Channel1 %s Channel2 %s",
				confno.Dat, sess.Env["channel"], bridgepeer.Dat))

		}
	}

}

func ConfBridgeSettings(sess *agi.Session) {
	var r = make(map[string]string)
	r["UserEvent"] = AGI2AMI
	r["Action"] = AGI2AMICONFBRIDGE
	r["Uniqueid"] = sess.Env["uniqueid"]
	amiAction(r)
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
			_, err = sess.Exec("ConfBridge", fmt.Sprintf("%s,,,%s", sess.Env["extension"], AMENU))
		} else {
			_, err = sess.Exec("ConfBridge", fmt.Sprintf("%s,,,%s", sess.Env["extension"], UMENU))
		}
		if err != nil {
			LoggerErr(err)
		}
	} else {
		_, err = sess.Exec("ConfBridge", fmt.Sprintf("%s,,,%s", sess.Env["extension"], UMENU))
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
		_, err := sess.Exec("DumpChan", "255")
		if err != nil {
			LoggerErr(err)
		}
		inner_num, err := strconv.Atoi(LEN_INNER_NUM)
		outer_num, err := strconv.Atoi(LEN_OUTER_NUM)
		if len(dst.Dat) == inner_num {
			CallbackCall(sess, dst.Dat, dst.Dat, dst.Dat, dst.Dat, false)
//			_, err = sess.Exec("Originate",
//				fmt.Sprintf("SIP/%s,exten,%s,%s,1", dst.Dat, CONFBRIDGE_CONFS, callerid))
		} else if len(dst.Dat) == outer_num {
			_, err := sess.SetVariable("CALLERID(num)", OUTPEER)

//			_, err = sess.Exec("Originate",
//				fmt.Sprintf("SIP/%s@%s,exten,%s,%s,1", dst.Dat, OUTPEER, CONFBRIDGE_CONFS, callerid))
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

//	_, err = sess.Exec("ChannelRedirect", fmt.Sprintf("%s,%s,%s,1", sess.Env["channel"], CONFBRIDGE_CONTEXT, sess.Env["extension"]))

	_, err = sess.Exec("ConfBridge", fmt.Sprintf("%s,,,%s", sess.Env["extension"], UMENU))
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
	rex, err := regexp.Compile(`^sip:(\S*)\@(\S*)\:(\S*)$`)
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
	rex2, err := regexp.Compile(`^sip:(\S*)\@(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$`)
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
	checkIP(BAN["ip"], sess)
}

//test
func checkIP(ipip string, sess *agi.Session) {
	useragent, err := sess.GetVariable("CHANNEL(useragent)")
	if err != nil {
		LoggerErr(err)
	}
	sipuri, err := sess.GetVariable("SIPURI")
	if err != nil {
		LoggerErr(err)
	}
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
				msg := fmt.Sprintf("User Agent: %s\nSIPURI: %s\nExtension: %s\nCallerid: %s",
					useragent.Dat, sipuri.Dat, sess.Env["extension"], sess.Env["callerid"])
				NotifyTG(msg)
				anet = true
				return
			}
		}
	}
	if anet == false {
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
	msg := fmt.Sprintf("Phreakers Attack: %s %sCountry: %s %sInetnum: %s %sRoute %s",
		ipip, _LT, country, _LT, inetnum, _LT, route)
	NotifyTG(msg)
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

func amiAction(mm map[string]string) {
	LoggerMap(mm)
	conn, _ := net.Dial("tcp", fmt.Sprintf("%s:%s", AMIhost, AMIport))
	fmt.Fprintf(conn, fmt.Sprintf("Action: Login%s", _LT))
	fmt.Fprintf(conn, fmt.Sprintf("Username: %s%s", AMIuser, _LT))
	fmt.Fprintf(conn, fmt.Sprintf("Secret: %s%s%s", AMIpass, _LT, _LT))
	buf := bytes.NewBufferString("")
	for k, v := range mm {
		buf.Write([]byte(k))
		buf.Write([]byte(_KVT))
		buf.Write([]byte(v))
		buf.Write([]byte(_LT))
		LoggerString(k)
		LoggerString(v)
	}
	buf.Write([]byte(_LT))
	fmt.Fprintf(conn, buf.String())
	fmt.Fprintf(conn, "Action: Logoff"+_LT+_LT)
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

func NotifyMail(action string, category string, message string, mailto string) {
	hname, err := os.Hostname()
	subj_hname := fmt.Sprintf("[%s]", strings.ToUpper(hname))
	subj_category := fmt.Sprintf("[%s]", strings.ToUpper(category))
	subj_action := fmt.Sprintf("[%s]", action)
	c, err := smtp.Dial(fmt.Sprintf("%s:%s", MAILSERVER, MAILPORT))
	if err != nil {
		LoggerString("Error: Cant connect to Mail server")
		LoggerErr(err)
	} else {
		c.Mail(fmt.Sprintf("%s@%s", hname, MAILDOMAIN))
		c.Rcpt(fmt.Sprintf("%s@%s", mailto, MAILDOMAIN))
		wc, err := c.Data()
		if err != nil {
			LoggerErr(err)
		}
		msg := []byte(fmt.Sprintf(MAILHEADER,
			_LT, mailto, MAILDOMAIN, _LT, subj_hname, subj_action, subj_category, _LT, _LT, message, _LT))
		_, err = wc.Write(msg)
		defer wc.Close()
		LoggerString(string(msg))
		if err != nil {
			LoggerErr(err)
		}
		err = wc.Close()
		if err != nil {
			LoggerErr(err)
		}
		c.Quit()
	}
	defer c.Close()
}

func decrypt(cipherstring string, keystring string) []byte {
	ciphertext := []byte(cipherstring)
	key := []byte(keystring)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	if len(ciphertext) < aes.BlockSize {
		panic("Text is too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)
	return ciphertext
}

func init() {
	k := os.Getenv("ASTCONFIG")
	f, err := os.Open(os.Getenv("ASTCONF"))

	if err != nil {
		LoggerString(err.Error())
	}
	data := make([]byte, 10000)
	count, err := f.Read(data)
	if err != nil {
		log.Fatal(err)
	}

	hasher := md5.New()
    	hasher.Write([]byte(k))
    	key := hex.EncodeToString(hasher.Sum(nil))

	content := string(data[:count])
	df := decrypt(content, key)
	c := bytes.NewReader(df)
	decoder := json.NewDecoder(c)
	conf := Config{}
	err = decoder.Decode(&conf)
	if err != nil {
		LoggerString(err.Error())
	}

	AMIport = conf.Ami.RemotePort
	AMIhost = conf.Ami.RemoteHost
	AMIuser = conf.Ami.Username
	AMIpass = conf.Ami.Password

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

	AGIHOST = conf.AgiServer.Host
	AGIPORT = conf.AgiServer.Port

	CALLBACKDST = conf.Callback.DstDir
	CALLBACKQUERY = conf.Callback.Query
	CALLBACKSET = conf.Callback.Set
	CALLBACKCONFBRIDGE = conf.Callback.SetConfbridge

	MAILSERVER = conf.Mail.Server
	MAILPORT = conf.Mail.Port
	MAILDOMAIN = conf.Mail.Domain
	MAILTO = conf.Mail.Mailto
	MAIL = conf.Mail.Mail
	MAILHEADER = conf.Mail.Header

	FAXDIR = conf.Fax.Dir
	FAXRECVSTR = conf.Fax.RecvStr
	FAXNUMS = conf.Fax.Nums

	BLOCKPSTNQUERY = conf.BlockFromPSTN.Query
	UEBLOCKEDABON = conf.UserEvents.BlockedAbon

	AGI2AMI = conf.UserEvents.AGI2AMI
	AGI2AMICONFBRIDGE = conf.UserEvents.AGI2AMIConfBridge

	BALDIR = conf.Balance.Dir
	BALDDIR = conf.Balance.DDir
	BALANCE = conf.Balance.Balance
	BALCONTRACT = conf.Balance.Contract
	BALNOMONEY = conf.Balance.FNoMoney
	BALONCONRACT = conf.Balance.FOnContract
	BALMINUS = conf.Balance.FMinus
	BALRICH  = conf.Balance.FRich
	BALRUB = conf.Balance.Rub
	BALKOP = conf.Balance.Kop

	LOGPATH = conf.LogDir.Path

	stdlog = log.New(os.Stdout, "", log.Ldate|log.Ltime)
	errlog = log.New(os.Stderr, "", log.Ldate|log.Ltime)
	NotifyTG("Start/Restart " + _DN + " " + _DD)
}

func main() {
	srv, err := daemon.New(_DN, _DD)
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

func LoggerMap(s map[string]string) {
  	tf := timeFormat()
	f, _ := os.OpenFile(LOGPATH+_DN, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
 	log.SetOutput(f)
  	log.Print(tf)
  	log.Print(s)
  	fmt.Println(s)
}

func LoggerString(s string) {
	tf := timeFormat()
	f, _ := os.OpenFile(LOGPATH+_DN, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	log.SetOutput(f)
	log.Print(tf)
	log.Print(s)
}

func LoggerByte(s byte) {
	tf := timeFormat()
	f, _ := os.OpenFile(LOGPATH+_DN, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	log.SetOutput(f)
	log.Print(tf)
	log.Print(s)
}

func LoggerAGI(s *agi.Session) {
	tf := timeFormat()
	f, _ := os.OpenFile(LOGPATH+_DN, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	log.SetOutput(f)
	log.Print(tf)
	log.Print(s)
}

func LoggerAGIReply(s agi.Reply) {
	tf := timeFormat()
	f, _ := os.OpenFile(LOGPATH+_DN, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	log.SetOutput(f)
	log.Print(tf)
	log.Print(s)
}

func LoggerMapMap(m map[string][]map[string]string) {
	f, _ := os.OpenFile(LOGPATH+_DN, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	log.SetOutput(f)
	log.Print(m)
}

func LoggerErr(e error) {
	f, _ := os.OpenFile(LOGPATH+_DN, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	log.SetOutput(f)
	log.Print(e)
}

func timeFormat() (string) {
	t := time.Now()
  	tf := fmt.Sprintf("%d-%02d-%02d %02d:%02d:%02d\n", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())
  	return tf
}
