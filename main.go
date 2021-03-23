package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type IPRecord struct {
	gorm.Model
	IP            string
	UnixTimestamp int64
	AccessCount   int
}

var listenAddr = flag.String("l", ":8080", "Listen Address")
var targetUrl = flag.String("t", "https://dcard.tw", "Target URL")
var accessCount = flag.Int("ac", 1000, "Access Count per hour")

var db *gorm.DB

func ipFilter(w http.ResponseWriter, req *http.Request) (handled bool) {
	forwardFor := req.Header.Get("X-Forwarded-For")
	forwardList := strings.Split(forwardFor, ", ")

	ips := strings.Split(req.RemoteAddr, ":")
	ip := ips[0]
	if len(forwardList) > 0 && len(forwardList[0]) > 0 {
		ip = forwardList[0]
	}

	var rec IPRecord
	rec.IP = ip

	now := time.Now()
	tm := now
	ac := 0
	res := db.Where(&rec).First(&rec)
	if res.Error != nil {
		if !errors.Is(res.Error, gorm.ErrRecordNotFound) {
			http.Error(w, res.Error.Error(), http.StatusInternalServerError)
			handled = true
			return
		}
	} else {
		tm = time.Unix(rec.UnixTimestamp, 0)
		ac = rec.AccessCount
	}

	tdelta := tm.Add(1 * time.Hour).Sub(now)
	if tdelta <= 0 {
		tm = now
		ac = 0
	} else {
		if ac >= *accessCount {
			fmt.Println("Restricted:", ip, "count:", ac)

			w.Header().Add("X-RateLimit-Remaining", "0")
			w.Header().Add("X-RateLimit-Reset", strconv.Itoa(int(tdelta.Seconds())))

			http.Error(w, "429 Too many requests", http.StatusTooManyRequests)
			handled = true
			return
		}
	}

	ac += 1
	rec.UnixTimestamp = tm.Unix()
	rec.AccessCount = ac

	w.Header().Add("X-RateLimit-Remaining", strconv.Itoa(*accessCount-ac))
	w.Header().Add("X-RateLimit-Reset", strconv.Itoa(int(tdelta.Seconds())))

	db.Save(&rec)

	return
}

func handler(w http.ResponseWriter, req *http.Request) {
	if ipFilter(w, req) {
		return
	}

	proxyReq, err := http.NewRequest(req.Method, *targetUrl+req.RequestURI, req.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	for k, vals := range req.Header {
		for _, v := range vals {
			proxyReq.Header.Add(k, v)
		}
	}

	resp, err := http.DefaultClient.Do(proxyReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}

	io.Copy(w, resp.Body)
}

func main() {
	flag.Parse()

	_db, err := gorm.Open(sqlite.Open("limiter.db"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		fmt.Println("db error:", err)
		os.Exit(1)
	}
	db = _db

	db.AutoMigrate(&IPRecord{})

	http.HandleFunc("/", handler)
	http.ListenAndServe(*listenAddr, nil)
}
