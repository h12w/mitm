package proxy

import (
	"compress/gzip"
	"io"
	"net/http"

	"appcoachs.net/x/log"
	"h12.me/errors"
	"h12.me/mitm"
)

type Proxy struct {
	certs          *mitm.CertPool
	roundTripper   http.RoundTripper
	RequestFilter  func(req *http.Request)
	ResponseFilter func(resp *http.Response)
}

func New(certs *mitm.CertPool, roundTripper http.RoundTripper) *Proxy {
	fp := &Proxy{
		certs:        certs,
		roundTripper: roundTripper,
	}

	return fp
}

func (p *Proxy) Serve(w http.ResponseWriter, req *http.Request) {
	if req.Method == "CONNECT" {
		err := p.certs.ServeHTTPS(w, req, p.serveHTTP)
		if err != nil {
			log.Error(errors.Wrap(err))
		}
	} else {
		p.serveHTTP(w, req)
	}
}

// Hop-by-hop headers. These are removed when sent to the backend.
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
var hopHeaders = []string{
	"Connection",
	"Proxy-Connection", // non-standard but still sent by libcurl and rejected by e.g. google
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",      // canonicalized version of "TE"
	"Trailer", // not Trailers per URL above; http://www.rfc-editor.org/errata_search.php?eid=4522
	"Transfer-Encoding",
	"Upgrade",
}

func (p *Proxy) serveHTTP(w http.ResponseWriter, req *http.Request) {
	req.RequestURI = ""

	if p.RequestFilter != nil {
		p.RequestFilter(req)
	}

	resp, err := p.roundTripper.RoundTrip(req)
	if err != nil {
		log.Error(errors.Wrap(err))
		return
	}

	for _, h := range hopHeaders {
		resp.Header.Del(h)
	}

	if resp.Header.Get("Content-Encoding") == "gzip" {
		body, err := newGzipReadCloser(resp.Body)
		if err == nil {
			resp.Body = body
			resp.ContentLength = -1
			resp.Header.Del("Content-Encoding")
			resp.Header.Del("Content-Length")
		}
	}
	defer resp.Body.Close()

	if p.ResponseFilter != nil {
		p.ResponseFilter(resp)
	}

	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Error(errors.Wrap(err))
	}
}

type gzipReadCloser struct {
	rc io.ReadCloser
	*gzip.Reader
}

func newGzipReadCloser(rc io.ReadCloser) (*gzipReadCloser, error) {
	reader, err := gzip.NewReader(rc)
	if err != nil {
		return nil, err
	}
	return &gzipReadCloser{
		rc:     rc,
		Reader: reader,
	}, nil
}

func (r *gzipReadCloser) Close() error {
	if err := r.rc.Close(); err != nil {
		return err
	}
	return r.Reader.Close()
}
