package socks

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// HTTP hop-by-hop 头：根据 RFC 7230 §6.1，不应跨代理转发。
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection", // 非标准但常见
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func removeHopByHopHeaders(h http.Header) {
	if c := h.Get("Connection"); c != "" {
		for name := range strings.SplitSeq(c, ",") {
			if name = strings.TrimSpace(name); name != "" {
				h.Del(name)
			}
		}
	}
	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
}

// splitHostPortDefault 分离 host 和 port，缺省端口时使用 defaultPort。
func splitHostPortDefault(addr, defaultPort string) (string, uint16, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		portStr = defaultPort
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port %q", portStr)
	}
	return host, uint16(port), nil
}

// writeHTTPStatus 向客户端写一个简短的状态行 + 空体响应。
func writeHTTPStatus(conn net.Conn, status string) {
	fmt.Fprintf(conn, "HTTP/1.1 %s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", status)
}

func (s *Server) handleHTTP(conn net.Conn, br *bufio.Reader) {
	start := time.Now()
	remote := conn.RemoteAddr().String()

	req, err := http.ReadRequest(br)
	if err != nil {
		log.Printf("[http] %s read request failed: %v", remote, err)
		writeHTTPStatus(conn, "400 Bad Request")
		return
	}

	if req.Method == http.MethodConnect {
		s.handleConnect(conn, req, start, remote)
		return
	}
	s.handleHTTPForward(conn, req, start, remote)
}

func (s *Server) handleConnect(conn net.Conn, req *http.Request, start time.Time, remote string) {
	host, port, err := splitHostPortDefault(req.Host, "443")
	if err != nil {
		log.Printf("[http] %s bad CONNECT host %q: %v", remote, req.Host, err)
		writeHTTPStatus(conn, "400 Bad Request")
		return
	}

	log.Printf("[http] %s CONNECT %s:%d", remote, host, port)

	dialCtx, dialCancel := context.WithTimeout(context.Background(), socksDialTimeout)
	tunnel, err := s.resolveAndDial(dialCtx, host, port)
	dialCancel()
	if err != nil {
		log.Printf("[http] %s connect %s:%d failed: %v", remote, host, port, err)
		writeHTTPStatus(conn, "502 Bad Gateway")
		return
	}
	defer tunnel.Close()

	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		log.Printf("[http] %s write 200 failed: %v", remote, err)
		return
	}
	conn.SetDeadline(time.Time{})

	bytesIn, bytesOut := bidirectionalCopy(conn, tunnel)
	s.Stats.BytesIn.Add(bytesIn)
	s.Stats.BytesOut.Add(bytesOut)

	dur := time.Since(start).Round(time.Millisecond)
	log.Printf("[http] %s CONNECT %s:%d closed, duration=%s in=%d out=%d", remote, host, port, dur, bytesIn, bytesOut)
}

func (s *Server) handleHTTPForward(conn net.Conn, req *http.Request, start time.Time, remote string) {
	if req.URL == nil || req.URL.Host == "" {
		log.Printf("[http] %s non-proxy request: %s %s", remote, req.Method, req.RequestURI)
		writeHTTPStatus(conn, "400 Bad Request")
		return
	}

	host, port, err := splitHostPortDefault(req.URL.Host, "80")
	if err != nil {
		log.Printf("[http] %s bad target %q: %v", remote, req.URL.Host, err)
		writeHTTPStatus(conn, "400 Bad Request")
		return
	}

	dialCtx, dialCancel := context.WithTimeout(context.Background(), socksDialTimeout)
	upstream, err := s.resolveAndDial(dialCtx, host, port)
	dialCancel()
	if err != nil {
		log.Printf("[http] %s dial %s:%d failed: %v", remote, host, port, err)
		writeHTTPStatus(conn, "502 Bad Gateway")
		return
	}
	defer upstream.Close()

	// 转发请求：剥掉 hop-by-hop 头并强制单连接（每次新建上游）。
	removeHopByHopHeaders(req.Header)
	req.Header.Set("Connection", "close")

	upstream.SetDeadline(time.Now().Add(socksHandshakeTimeout))
	if err := req.Write(upstream); err != nil {
		log.Printf("[http] %s write upstream failed: %v", remote, err)
		return
	}
	upstream.SetDeadline(time.Time{})

	resp, err := http.ReadResponse(bufio.NewReader(upstream), req)
	if err != nil {
		log.Printf("[http] %s read upstream response failed: %v", remote, err)
		writeHTTPStatus(conn, "502 Bad Gateway")
		return
	}
	defer resp.Body.Close()
	removeHopByHopHeaders(resp.Header)
	resp.Close = true

	conn.SetDeadline(time.Time{})
	bytesOut, err := writeResponseAndCount(conn, resp)
	if err != nil {
		log.Printf("[http] %s write client response failed: %v", remote, err)
		return
	}
	s.Stats.BytesOut.Add(bytesOut)

	dur := time.Since(start).Round(time.Millisecond)
	log.Printf("[http] %s %s %s -> %s:%d %d duration=%s out=%d",
		remote, req.Method, req.URL.RequestURI(), host, port, resp.StatusCode, dur, bytesOut)
}

// writeResponseAndCount 把 resp 写到 client，返回写出的字节数。
// 用 countingWriter 而不是直接 resp.Write，因为后者不返回字节数。
func writeResponseAndCount(client net.Conn, resp *http.Response) (int64, error) {
	cw := &countingWriter{w: client}
	err := resp.Write(cw)
	return cw.n, err
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
