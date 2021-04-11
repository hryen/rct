package main

import (
	"bytes"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

var hostsFile, defaultPort, defaultUsername, defaultPassword string
var showVersion bool

var (
	InfoLogger  *log.Logger
	ErrorLogger *log.Logger
)

var savePath = "files"

func init() {
	flag.StringVar(&hostsFile, "h", "", "hosts file")
	flag.StringVar(&defaultPort, "P", "22", "default port, if not specified in the hosts file")
	flag.StringVar(&defaultUsername, "u", "", "default username, if not specified in the hosts file")
	flag.StringVar(&defaultPassword, "p", "", "default password, if not specified in the hosts file")
	flag.BoolVar(&showVersion, "v", false, "output version information and exit")

	// 日志
	flags := log.Ldate | log.Lmicroseconds
	InfoLogger = log.New(os.Stdout, "INFO: ", flags)
	ErrorLogger = log.New(os.Stderr, "ERROR: ", flags)
}

// TODO 可指定文件保存的目录
// TODO hosts.txt文件中的密码使用加密的方式
// TODO 可指定日志保存的文件
func main() {
	flag.Parse()

	if showVersion {
		fmt.Print("rct Version 0.0.1")
		os.Exit(0)
	}

	if hostsFile == "" {
		fmt.Println("Usage: rct -h HOSTS_FILE [OPTION]...")
		fmt.Println("Run command tool")
		flag.PrintDefaults()
		os.Exit(1)
	}

	hosts, err := readFile(hostsFile)
	if err != nil {
		fmt.Print("Load hosts error:", err)
		os.Exit(1)
	}

	_, err = os.Stat(savePath)
	if os.IsNotExist(err) {
		err = os.Mkdir(savePath, 0755)
		if err != nil {
			ErrorLogger.Print("Create directory error: ", err)
			os.Exit(1)
		}
	}

	defer timeCost(time.Now())

	// 设备数量
	hostCount := 0
	var wg sync.WaitGroup
	// 从第二行开始循环
	for i := 1; i < len(hosts); i++ {
		hostItem := hosts[i]
		// 跳过空行
		if strings.TrimSpace(hostItem) == "" {
			continue
		}
		// 读取 host, port, username, password, commandFile
		hostItemArr := strings.Split(hostItem, ",")
		host := hostItemArr[0]
		port := hostItemArr[1]
		if "" == port {
			port = defaultPort
		}
		username := hostItemArr[2]
		if "" == username {
			username = defaultUsername
		}
		password := hostItemArr[3]
		if "" == password {
			password = defaultPassword
		}

		commandFile := hostItemArr[4]
		commands, err := readFile(commandFile)
		if err != nil {
			ErrorLogger.Print("Host "+host+" Error: Load commands error:", err)
			continue
		}

		// 执行命令然后把回显的内容保存到文件
		wg.Add(1)
		go func(host string, wg *sync.WaitGroup) {
			defer wg.Done()
			RunCommandWriteFile(savePath+"/"+host+".txt", host, port, username, password, commands)
		}(host, &wg)
		hostCount++
	}
	wg.Wait()

	InfoLogger.Printf("Host total: %d", hostCount)
}

func readFile(file string) ([]string, error) {
	bs, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	content := string(bs)
	content = strings.ReplaceAll(content, "\r\n", "\n")

	return strings.Split(content, "\n"), nil
}

func RunCommandWriteFile(filename, host, port, username, password string, commands []string) {
	out, err := RunCommand(host, port, username, password, commands)
	if err != nil {
		ErrorLogger.Print("Host "+host+" Error: ", err)
		return
	}

	err = ioutil.WriteFile(filename, out, 0644)
	if err != nil {
		ErrorLogger.Print("Host "+host+" Error: write file error: ", err)
		return
	}
	InfoLogger.Print("Host " + host + " Done")
}

func RunCommand(host, port, username, password string, commands []string) ([]byte, error) {
	var kexAlgos = []string{
		"curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256",
		"ecdh-sha2-nistp384",
		"ecdh-sha2-nistp521",
		"diffie-hellman-group14-sha1",
		"diffie-hellman-group1-sha1",
	}
	var ciphers = []string{
		"aes128-ctr", "aes192-ctr", "aes256-ctr",
		"aes128-gcm@openssh.com",
		"chacha20-poly1305@openssh.com",
		"arcfour256", "arcfour128", "arcfour",
		"aes128-cbc",
		"3des-cbc",
	}

	config := &ssh.ClientConfig{
		Timeout:         5 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		User:            username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		Config: ssh.Config{
			KeyExchanges: kexAlgos,
			Ciphers:      ciphers,
		},
	}

	client, err := ssh.Dial("tcp", host+":"+port, config)
	if err != nil {
		return nil, err
	}
	defer func(client *ssh.Client) {
		_ = client.Close()
	}(client)

	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer func(session *ssh.Session) {
		_ = session.Close()
	}(session)

	var sout bytes.Buffer
	var serr bytes.Buffer
	session.Stdout = &sout
	session.Stderr = &serr

	stdin, err := session.StdinPipe()
	if err != nil {
		return nil, err
	}

	err = session.Shell()
	if err != nil {
		return nil, err
	}

	for _, cmd := range commands {
		_, err = fmt.Fprintf(stdin, "%s\n", cmd)
		if err != nil {
			return nil, err
		}
	}

	_ = session.Wait()
	return append(sout.Bytes(), serr.Bytes()...), nil
}

func timeCost(start time.Time) {
	tc := time.Since(start)
	InfoLogger.Printf("Time consuming: %v\n", tc)
}
