package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/aws/signer/v4"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"

	uuid "github.com/satori/go.uuid"
)

// set a default global logger
var logger = log.NewJSONLogger(os.Stderr)

type requestStruct struct {
	Requestid  string
	Datetime   string
	Remoteaddr string
	Requesturi string
	Method     string
	Statuscode int
	Elapsed    float64
	Body       string
}

type responseStruct struct {
	Requestid string
	Body      string
}

type proxy struct {
	scheme         string
	host           string
	region         string
	service        string
	endpointHeader string
	verbose        bool
	prettify       bool
	logtofile      bool
	fileRequest    *os.File
	fileResponse   *os.File
	credentials    *credentials.Credentials
	client         *http.Client
}

func newProxy(args ...interface{}) *proxy {
	return &proxy{
		endpointHeader: args[0].(string),
		verbose:        args[1].(bool),
		prettify:       args[2].(bool),
		logtofile:      args[3].(bool),
	}
}

var client = &http.Client{
	CheckRedirect: noRedirect,
	Timeout:       300 * time.Second,
}

func noRedirect(req *http.Request, via []*http.Request) error {
	return http.ErrUseLastResponse
}

type esSigningEndpoint struct {
	scheme  string
	host    string
	region  string
	service string
}

func parseESEndpoint(endpoint string) (*esSigningEndpoint, error) {
	var link *url.URL
	var err error
	signingEnpoint := esSigningEndpoint{}

	if link, err = url.Parse(endpoint); err != nil {
		return nil, fmt.Errorf("error: failure while parsing endpoint: %s. Error: %s",
			endpoint, err.Error())
	}

	// Only http/https are supported schemes
	switch link.Scheme {
	case "http", "https":
	default:
		link.Scheme = "https"
	}

	// Unknown schemes sometimes result in empty host value
	if link.Host == "" {
		return nil, fmt.Errorf("error: empty host or protocol information in submitted endpoint (%s)",
			endpoint)
	}

	// AWS SignV4 enabled, extract required parts for signing process
	// Extract region and service from link
	parts := strings.Split(link.Host, ".")

	// search-$es_domain.us-east-1.es.amazonaws.com
	// https://search-domtest-doo7owbl6h26rve2aneagyhdzm.us-east-1.es.amazonaws.com/_plugin/kibana/

	if len(parts) == 5 {
		signingEnpoint.region, signingEnpoint.service = parts[1], parts[2]
	} else {
		return nil, fmt.Errorf("error: submitted endpoint is not a valid Amazon ElasticSearch Endpoint")
	}

	// Update proxy struct
	signingEnpoint.scheme = link.Scheme
	signingEnpoint.host = link.Host

	return &signingEnpoint, nil
}

func (p *proxy) getSigner() *v4.Signer {
	// Refresh credentials after expiration. Required for STS
	if p.credentials == nil {
		sess := session.Must(session.NewSession())
		credentials := sess.Config.Credentials
		p.credentials = credentials
		level.Info(logger).Log("msg", "session expired, generated fresh aws credentials object")
	}
	return v4.NewSigner(p.credentials)
}

func (p *proxy) getEndpointFromRequestHeader(r *http.Request) (*esSigningEndpoint, error) {

	headerValue := r.Header.Get(p.endpointHeader)
	if len(headerValue) > 0 {
		r.Header.Del(p.endpointHeader)
		return parseESEndpoint(headerValue)
	}
	return nil, fmt.Errorf("Request does not contain the ES Endpoint Header we are signing the request for: (%s)", p.endpointHeader)
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestStarted := time.Now()
	dump, err := httputil.DumpRequest(r, true)

	if err != nil {
		level.Error(logger).Log("msg", "error while dumping request", "err", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	defer r.Body.Close()

	ep := *r.URL
	ep.Path = path.Clean(ep.Path)

	// Make signV4 optional
	// Start AWS session from ENV, Shared Creds or EC2Role
	signer := p.getSigner()
	esEndpoint, err := p.getEndpointFromRequestHeader(r)

	if err != nil {
		level.Error(logger).Log("msg", "Error while parsing ES Endpoint header", "err", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ep.Host = esEndpoint.host
	ep.Scheme = esEndpoint.scheme

	req, err := http.NewRequest(r.Method, ep.String(), r.Body)
	if err != nil {
		level.Error(logger).Log("msg", "BadGateway", "err", err.Error(), "request", req.URL.String())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	addHeaders(r.Header, req.Header)

	// Sign the request with AWSv4
	payload := bytes.NewReader(replaceBody(req))
	signer.Sign(req, payload, esEndpoint.service, esEndpoint.region, time.Now())

	resp, err := client.Do(req)
	if err != nil {
		level.Error(logger).Log("msg", "BadGateway", "err", err.Error(), "request", req.URL.String())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// AWS credentials expired, need to generate fresh ones
	if resp.StatusCode == 403 {
		p.credentials = nil
		return
	}

	defer resp.Body.Close()

	// Write back headers to requesting client
	copyHeaders(w.Header(), resp.Header)

	// Send response back to requesting client
	body := bytes.Buffer{}
	if _, err := io.Copy(&body, resp.Body); err != nil {
		level.Error(logger).Log("msg", "something went wrong", "err", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(body.Bytes())

	requestEnded := time.Since(requestStarted)

	/*############################
	## Logging
	############################*/

	rawQuery := string(dump)
	rawQuery = strings.Replace(rawQuery, "\n", " ", -1)
	regex, _ := regexp.Compile("{.*}")
	regEx, _ := regexp.Compile("_msearch|_bulk")
	queryEx := regEx.FindString(rawQuery)

	var query string

	if len(queryEx) == 0 {
		query = regex.FindString(rawQuery)
	} else {
		query = ""
	}

	if p.verbose {
		level.Info(logger).Log("method", r.Method, "remoteAddress", r.RemoteAddr, "requestUri", ep.RequestURI(), "query", query, "status", resp.StatusCode, "timeElapsed", requestEnded.Seconds())
	}
}

// Recent versions of ES/Kibana require
// "kbn-version", "kbn-xsrf", "authorization" and "content-type: application/json"
// headers to exist in the request.
// If missing requests fails.
func addHeaders(src, dest http.Header) {
	if val, ok := src["Kbn-Version"]; ok {
		dest.Add("Kbn-Version", val[0])
	}

	if val, ok := src["Content-Type"]; ok {
		dest.Add("Content-Type", val[0])
	}

	if val, ok := src["Kbn-Xsrf"]; ok {
		dest.Add("Kbn-Xsrf", val[0])
	}

	if val, ok := src["Authorization"]; ok {
		dest.Add("Authorization", val[0])
	}
}

// Signer.Sign requires a "seekable" body to sum body's sha256
func replaceBody(req *http.Request) []byte {
	if req.Body == nil {
		return []byte{}
	}
	payload, _ := ioutil.ReadAll(req.Body)
	req.Body = ioutil.NopCloser(bytes.NewReader(payload))
	return payload
}

func copyHeaders(dst, src http.Header) {
	for k, vals := range src {
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

func init() {
	// ensure global logger uses UTC timestamps
	logger = log.With(logger, "timestamp", log.DefaultTimestampUTC)
}

func main() {

	var (
		verbose        bool
		prettify       bool
		logtofile      bool
		endpointHeader string
		listenAddress  string
		fileRequest    *os.File
		fileResponse   *os.File
		err            error
	)

	flag.StringVar(&endpointHeader, "endpoint-header", "X-ES-Endpoint", "The Header that contains Amazon ElasticSearch Endpoint (e.g: https://dummy-host.eu-west-1.es.amazonaws.com)")
	flag.StringVar(&listenAddress, "listen", "127.0.0.1:9200", "Local TCP port to listen on")
	flag.BoolVar(&verbose, "verbose", false, "Print user requests")
	flag.BoolVar(&logtofile, "log-to-file", false, "Log user requests and ElasticSearch responses to files")
	flag.BoolVar(&prettify, "pretty", false, "Prettify verbose and file output")
	flag.Parse()

	p := newProxy(
		endpointHeader,
		verbose,
		prettify,
		logtofile,
	)

	if p.logtofile {
		u1, _ := uuid.NewV4()
		u2, _ := uuid.NewV4()
		requestFname := fmt.Sprintf("request-%s.log", u1.String())
		responseFname := fmt.Sprintf("response-%s.log", u2.String())

		if fileRequest, err = os.Create(requestFname); err != nil {
			level.Error(logger).Log("msg", err.Error())
			os.Exit(1) // go-kit/log doesn't have a level.Fatal so we're exiting with os.Exit(1)
		}
		if fileResponse, err = os.Create(responseFname); err != nil {
			level.Error(logger).Log("msg", err.Error())
			os.Exit(1) // go-kit/log doesn't have a level.Fatal so we're exiting with os.Exit(1)
		}

		defer fileRequest.Close()
		defer fileResponse.Close()

		p.fileRequest = fileRequest
		p.fileResponse = fileResponse

	}

	level.Info(logger).Log("status", "starting")
	level.Info(logger).Log("status", "started", "listening", listenAddress)
	level.Error(logger).Log("status", "failed", "err", http.ListenAndServe(listenAddress, p))

}
