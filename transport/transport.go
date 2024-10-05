package transport

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/juruen/rmapi/log"
	"github.com/juruen/rmapi/model"
	"github.com/juruen/rmapi/util"
)

type AuthType int

type BodyString struct {
	Content string
}

var ErrUnauthorized = errors.New("401 Unauthorized")
var ErrConflict = errors.New("409 Conflict")

var RmapiUserAGent = "rmapi"

const (
	EmptyBearer AuthType = iota
	DeviceBearer
	UserBearer
)

const (
	EmptyBody string = ""
)

type HttpClientCtx struct {
	Client *http.Client
	Tokens model.AuthTokens
}

func CreateHttpClientCtx(tokens model.AuthTokens) HttpClientCtx {
	f, err := os.OpenFile("/tmp/keys", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}
	var httpClient = &http.Client{
		Timeout: 5 * 60 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				KeyLogWriter: f,
			},
		},
	}

	return HttpClientCtx{httpClient, tokens}
}

func (ctx HttpClientCtx) addAuthorization(req *http.Request, authType AuthType) {
	var header string

	switch authType {
	case EmptyBearer:
		header = "Bearer"
	case DeviceBearer:
		header = fmt.Sprintf("Bearer %s", ctx.Tokens.DeviceToken)
	case UserBearer:
		header = fmt.Sprintf("Bearer %s", ctx.Tokens.UserToken)
	}

	req.Header.Add("Authorization", header)
}

func (ctx HttpClientCtx) Get(authType AuthType, url string, body interface{}, target interface{}) error {
	bodyReader, err := util.ToIOReader(body)

	if err != nil {
		log.Error.Println("failed to serialize body", err)
		return err
	}

	response, err := ctx.Request(authType, http.MethodGet, url, bodyReader)

	if response != nil {
		defer response.Body.Close()
	}

	if err != nil {
		return err
	}

	return json.NewDecoder(response.Body).Decode(target)
}

func (ctx HttpClientCtx) GetStream(authType AuthType, url string) (io.ReadCloser, error) {
	response, err := ctx.Request(authType, http.MethodGet, url, strings.NewReader(""))

	var respBody io.ReadCloser
	if response != nil {
		respBody = response.Body
	}

	return respBody, err
}

func (ctx HttpClientCtx) Post(authType AuthType, url string, reqBody, resp interface{}) error {
	return ctx.httpRawReq(authType, http.MethodPost, url, reqBody, resp)
}

func (ctx HttpClientCtx) Put(authType AuthType, url string, reqBody, resp interface{}) error {
	return ctx.httpRawReq(authType, http.MethodPut, url, reqBody, resp)
}

func (ctx HttpClientCtx) PutStream(authType AuthType, url string, reqBody io.Reader) error {
	return ctx.httpRawReq(authType, http.MethodPut, url, reqBody, nil)
}

func (ctx HttpClientCtx) Delete(authType AuthType, url string, reqBody, resp interface{}) error {
	return ctx.httpRawReq(authType, http.MethodDelete, url, reqBody, resp)
}

func (ctx HttpClientCtx) httpRawReq(authType AuthType, verb, url string, reqBody, resp interface{}) error {
	var contentBody io.Reader

	switch reqBody.(type) {
	case io.Reader:
		contentBody = reqBody.(io.Reader)
	default:
		c, err := util.ToIOReader(reqBody)

		if err != nil {
			log.Error.Println("failed to serialize body", err)
			return nil
		}

		contentBody = c
	}

	response, err := ctx.Request(authType, verb, url, contentBody)

	if response != nil {
		defer response.Body.Close()
	}

	if err != nil {
		return err
	}

	// We want to ingore the response
	if resp == nil {
		return nil
	}

	switch resp.(type) {
	case *BodyString:
		bodyContent, err := ioutil.ReadAll(response.Body)

		if err != nil {
			return err
		}

		resp.(*BodyString).Content = string(bodyContent)
	default:
		err := json.NewDecoder(response.Body).Decode(resp)

		if err != nil {
			log.Error.Println("failed to deserialize body", err, response.Body)
			return err
		}
	}
	return nil
}

func (ctx HttpClientCtx) Request(authType AuthType, verb, url string, body io.Reader) (*http.Response, error) {
	request, err := http.NewRequest(verb, url, body)
	if err != nil {
		return nil, err
	}

	ctx.addAuthorization(request, authType)
	request.Header.Add("User-Agent", RmapiUserAGent)

	if log.TracingEnabled {
		drequest, err := httputil.DumpRequest(request, true)
		log.Trace.Printf("request: %s %v", string(drequest), err)
	}

	response, err := ctx.Client.Do(request)

	if err != nil {
		log.Error.Println("http request failed with", err)
		return nil, err
	}

	if log.TracingEnabled {
		defer response.Body.Close()
		dresponse, err := httputil.DumpResponse(response, true)
		log.Trace.Printf("%s %v", string(dresponse), err)
	}

	if response.StatusCode != 200 {
		log.Trace.Printf("request failed with status %d\n", response.StatusCode)
	}

	switch response.StatusCode {
	case http.StatusOK:
		return response, nil
	case http.StatusUnauthorized:
		return response, ErrUnauthorized
	case http.StatusConflict:
		return response, ErrConflict
	default:
		return response, fmt.Errorf("request failed with status %d", response.StatusCode)
	}
}

func (ctx HttpClientCtx) GetBlobStream(url string) (io.ReadCloser, int64, error) {
	log.Trace.Printf("Get Blob Stream %s", url)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	ctx.addAuthorization(req, UserBearer)
	response, err := ctx.Client.Do(req)

	if err != nil {
		return nil, 0, err
	}
	if response.StatusCode == http.StatusNotFound {
		return nil, 0, ErrNotFound
	}
	if response.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("GetBlobStream, status code not ok %d", response.StatusCode)
	}
	return response.Body, 0, err
}

// those headers are case sensitive
const HeaderGeneration = "x-goog-generation"
const HeaderContentLengthRange = "x-goog-content-length-range"
const HeaderGenerationIfMatch = "x-goog-if-generation-match"

const HeaderContentMD5 = "Content-MD5"

var ErrWrongGeneration = errors.New("wrong generation")
var ErrNotFound = errors.New("not found")

func addSizeHeader(req *http.Request, maxRequestSize int64) {
	if maxRequestSize > 0 {
		//don't change the header case, signed headers
		req.Header[HeaderContentLengthRange] = []string{fmt.Sprintf("0,%d", maxRequestSize)}
	}
}
func addGenerationMatchHeader(req *http.Request, gen int64) {
	if gen > 0 {
		req.Header[HeaderGenerationIfMatch] = []string{strconv.FormatInt(gen, 10)}
	}
}

func (ctx HttpClientCtx) PutRootBlobStream(url string, roothash string, gen int64) (newGeneration int64, err error) {
	requestBody, err := json.Marshal(model.PutRootRequest{
		Generation: gen,
		Hash:       roothash,
		Broadcast:  true,
	})
	if err != nil {
		panic(err)
	}

	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(requestBody))
	if err != nil {
		return
	}
	req.Header.Add("User-Agent", RmapiUserAGent)
	ctx.addAuthorization(req, UserBearer)

	if log.TracingEnabled {
		drequest, err := httputil.DumpRequest(req, true)
		log.Trace.Printf("PutRootBlobStream: %s %v", string(drequest), err)
	}
	response, err := ctx.Client.Do(req)
	if err != nil {
		return
	}

	if log.TracingEnabled {
		defer response.Body.Close()
		dresponse, err := httputil.DumpResponse(response, true)
		log.Trace.Printf("PutRootBlobStream:Response: %s %v", string(dresponse), err)
	}

	if response.StatusCode == http.StatusPreconditionFailed {
		return 0, ErrWrongGeneration
	}
	if response.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("PutRootBlobStream: got status code %d", response.StatusCode)
	}

	var responseBody model.RootRequest
	err = json.NewDecoder(response.Body).Decode(&responseBody)
	if err != nil {
		panic(err)
	}

	log.Trace.Println("new generation: ", responseBody.Generation)
	newGeneration = responseBody.Generation
	return
}
func (ctx HttpClientCtx) PutBlobStream(url string, reader io.Reader, size int64, checksum uint32) (err error) {
	req, err := http.NewRequest(http.MethodPut, url, reader)
	if err != nil {
		return
	}
	req.ContentLength = size
	req.Header.Add("User-Agent", RmapiUserAGent)
	req.Header.Add("Content-Type", "application-octet-stream")
	checksumBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(checksumBytes, checksum)
	req.Header.Add("x-goog-hash", "crc32c="+base64.StdEncoding.EncodeToString(checksumBytes))
	ctx.addAuthorization(req, UserBearer)

	if log.TracingEnabled {
		drequest, err := httputil.DumpRequest(req, true)
		log.Trace.Printf("PutBlobStream: %s %v", string(drequest), err)
	}
	response, err := ctx.Client.Do(req)
	if err != nil {
		return
	}

	if log.TracingEnabled {
		defer response.Body.Close()
		dresponse, err := httputil.DumpResponse(response, true)
		log.Trace.Printf("PutBlobSteam: Response: %s %v", string(dresponse), err)
	}

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("PutBlobStream: got status code %d", response.StatusCode)
	}

	return nil
}
