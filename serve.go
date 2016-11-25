package mitm

import (
	"bufio"
	"bytes"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"

	"h12.me/errors"
)

// ServeHTTPS intercepts an HTTPS request and serve it as a normal HTTP request
func (pool *CertPool) ServeHTTPS(w http.ResponseWriter, req *http.Request, serve func(w http.ResponseWriter, req *http.Request)) error {
	conn, err := pool.hijack(w, req)
	if err != nil {
		return err
	}
	defer conn.Close()

	realReq, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		return errors.Wrap(err)
	}
	requestURI := "https://" + req.RequestURI + realReq.RequestURI
	uri, err := url.Parse(requestURI)
	if err != nil {
		return errors.Wrap(err)
	}
	realReq.RequestURI = requestURI
	realReq.URL = uri

	writer := newResponseWriter()
	serve(writer, realReq)
	return writer.finish(conn)
}
func (pool *CertPool) hijack(w http.ResponseWriter, req *http.Request) (net.Conn, error) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("cannot hijack the ResponseWriter")
	}
	tlsConn, _, err := hijacker.Hijack()
	if err != nil {
		return nil, errors.Wrap(err)
	}
	if _, err := tlsConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
		tlsConn.Close()
		return nil, errors.Wrap(err)
	}
	host, _, _ := net.SplitHostPort(req.URL.Host)
	conn, err := pool.fakeSecureConn(tlsConn, host)
	if err != nil {
		tlsConn.Close()
		return nil, err
	}
	return conn, nil
}

type responseWriter struct {
	code   int
	header http.Header
	buf    bytes.Buffer
}

func newResponseWriter() *responseWriter {
	return &responseWriter{
		code:   http.StatusOK,
		header: make(http.Header),
	}
}

func (w *responseWriter) Header() http.Header            { return w.header }
func (w *responseWriter) WriteHeader(code int)           { w.code = code }
func (w *responseWriter) Write(body []byte) (int, error) { return w.buf.Write(body) }

func (w *responseWriter) finish(conn net.Conn) error {
	resp := http.Response{
		Status:     http.StatusText(w.code),
		StatusCode: w.code,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     w.header,
		Body:       ioutil.NopCloser(&w.buf),
		Close:      true,
	}
	return errors.Wrap(resp.Write(conn))
}
