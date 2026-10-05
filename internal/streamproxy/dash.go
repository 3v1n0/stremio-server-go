// SPDX-FileCopyrightText: 2026 Gianluca Boiano
//
// SPDX-License-Identifier: MIT

package streamproxy

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
)

func init() {
	mpdHandler = dashServe
}

// dashServe handles MPEG-DASH MPD proxy requests at /proxy/mpd/manifest.m3u8.
func dashServe(h *Handler, w http.ResponseWriter, r *http.Request) {
	if err := h.authorize(r); err != nil {
		writeAuthError(w, err)
		return
	}
	opts, err := h.parseOptions(r)
	if err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if opts.Dest == "" {
		http.Error(w, "missing destination", http.StatusBadRequest)
		return
	}
	if err := h.ValidateDest(opts.Dest); err != nil {
		http.Error(w, "forbidden destination", http.StatusForbidden)
		return
	}
	if h.rejectBlockedProxyHost(w, opts.Proxy) {
		return
	}
	effProxy := opts.Proxy
	if effProxy == "" {
		effProxy = h.cfg.UpstreamProxy
	}
	resp, err := h.fetch(r.Context(), http.MethodGet, opts.Dest, opts.ReqHeaders, nil, effProxy)
	if err != nil {
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestBytes+1))
	if err != nil {
		http.Error(w, "read error: "+err.Error(), http.StatusBadGateway)
		return
	}
	if len(body) > maxManifestBytes {
		http.Error(w, "upstream manifest too large", http.StatusBadGateway)
		return
	}
	out := dashRewrite(h, r, opts, body)
	w.Header().Set("Content-Type", "application/dash+xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

// dashQueryEscape is like url.QueryEscape but leaves '$', '(', and ')' unencoded.
// MPEG-DASH SegmentTemplate URIs embed '$Variable$' placeholder tokens that must
// survive the encoding so the DASH client can perform template expansion before
// requesting each segment through the proxy.
func dashQueryEscape(s string) string {
	e := url.QueryEscape(s)
	e = strings.ReplaceAll(e, "%24", "$")
	e = strings.ReplaceAll(e, "%28", "(")
	e = strings.ReplaceAll(e, "%29", ")")
	return e
}

// dashBuildTemplateURL constructs a /proxy/stream URL for a SegmentTemplate
// initialization or media attribute.  The destination is placed as a plain
// (non-base64) query-escaped value so embedded $…$ placeholder tokens remain
// visible to the DASH client for template expansion.  Auth parameters from opts
// are propagated exactly as buildProxyURL does.
func dashBuildTemplateURL(h *Handler, ext, abs string, opts *Options) string {
	// F3: strings.Builder avoids the O(N) reallocation ladder from string += in header loops.
	var b strings.Builder
	b.Grow(256)
	b.WriteString(ext)
	b.WriteString("/proxy/stream?d=")
	b.WriteString(dashQueryEscape(abs))
	if opts != nil {
		for k, vs := range opts.ReqHeaders {
			for _, v := range vs {
				b.WriteString("&h_")
				b.WriteString(url.QueryEscape(k))
				b.WriteByte('=')
				b.WriteString(url.QueryEscape(v))
			}
		}
		for k, vs := range opts.RespHeaders {
			for _, v := range vs {
				b.WriteString("&r_")
				b.WriteString(url.QueryEscape(k))
				b.WriteByte('=')
				b.WriteString(url.QueryEscape(v))
			}
		}
		if opts.APIPassword != "" {
			b.WriteString("&api_password=")
			b.WriteString(url.QueryEscape(opts.APIPassword))
		}
		if opts.Proxy != "" {
			b.WriteString("&proxy=")
			b.WriteString(url.QueryEscape(opts.Proxy))
		}
	}
	return b.String()
}

// dashRewrite rewrites URL-bearing tokens in an MPEG-DASH MPD document so that
// all media references are routed through the proxy.  It tokenises with
// xml.Decoder.RawToken (no namespace translation) and copies every untouched
// token verbatim from the input using byte offsets, so namespace declarations
// (xmlns, xmlns:xsi, ...), prefixed attributes (xsi:schemaLocation,
// cenc:default_KID, ...), comments, and whitespace survive unchanged.  Only
// start tags whose attributes are rewritten are re-serialised, keeping prefixes
// and escaping attribute values.
//
// Rewritten tokens:
//   - <BaseURL> character data — resolved and proxied via /proxy/stream
//     (buildProxyURL, base64-encoded destination).
//   - <SegmentTemplate initialization="…" media="…"> attributes — resolved and
//     proxied via dashBuildTemplateURL, which keeps $…$ placeholders unencoded.
//   - <SegmentURL media="…" index="…"> attributes — resolved and proxied via
//     buildProxyURL (base64-encoded destination, no placeholders).
//   - <Initialization sourceURL="…"> attribute — resolved and proxied via
//     buildProxyURL; the range attribute is left untouched.
//
// If XML tokenisation fails at any point, or the element nesting is not
// balanced, the original bytes are returned unchanged (best-effort; no panics).
//
// Limitation: nested BaseURL chains are each resolved against opts.Dest rather
// than against each other's accumulated base.
func dashRewrite(h *Handler, r *http.Request, opts *Options, mpd []byte) []byte {
	dec := xml.NewDecoder(bytes.NewReader(mpd))
	var buf bytes.Buffer

	extBase := h.externalBase(r)
	inBaseURL := false
	var stack []string
	var prev int64

	for {
		tok, err := dec.RawToken()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return mpd
		}
		cur := dec.InputOffset()
		raw := mpd[prev:cur]
		prev = cur

		switch t := tok.(type) {
		case xml.StartElement:
			stack = append(stack, dashQName(t.Name))

			changed := false
			rewrite := func(i int, v string) {
				t.Attr[i].Value = v
				changed = true
			}
			switch t.Name.Local {
			case "BaseURL":
				inBaseURL = true

			case "SegmentTemplate":
				for i, attr := range t.Attr {
					switch attr.Name.Local {
					case "initialization", "media":
						abs := resolveURL(opts.Dest, attr.Value)
						rewrite(i, dashBuildTemplateURL(h, extBase, abs, opts))
					}
				}

			case "SegmentURL":
				for i, attr := range t.Attr {
					switch attr.Name.Local {
					case "media", "index":
						if attr.Value != "" {
							abs := resolveURL(opts.Dest, attr.Value)
							rewrite(i, h.buildProxyURL(extBase, "/proxy/stream", abs, opts))
						}
					}
				}

			case "Initialization":
				for i, attr := range t.Attr {
					if attr.Name.Local == "sourceURL" {
						abs := resolveURL(opts.Dest, attr.Value)
						rewrite(i, h.buildProxyURL(extBase, "/proxy/stream", abs, opts))
					}
				}
			}

			if !changed {
				buf.Write(raw)
				continue
			}
			buf.WriteByte('<')
			buf.WriteString(dashQName(t.Name))
			for _, a := range t.Attr {
				buf.WriteByte(' ')
				buf.WriteString(dashQName(a.Name))
				buf.WriteString(`="`)
				if err := xml.EscapeText(&buf, []byte(a.Value)); err != nil {
					return mpd
				}
				buf.WriteByte('"')
			}
			if bytes.HasSuffix(raw, []byte("/>")) {
				buf.WriteByte('/')
			}
			buf.WriteByte('>')

		case xml.EndElement:
			inBaseURL = false
			if len(stack) == 0 || stack[len(stack)-1] != dashQName(t.Name) {
				return mpd
			}
			stack = stack[:len(stack)-1]
			// The synthetic end of a self-closing tag consumes no input
			// (raw is empty); the start tag already carried the "/>".
			buf.Write(raw)

		case xml.CharData:
			if inBaseURL {
				trimmed := strings.TrimSpace(string(t))
				if trimmed != "" {
					abs := resolveURL(opts.Dest, trimmed)
					proxied := h.buildProxyURL(extBase, "/proxy/stream", abs, opts)
					inBaseURL = false // consumed; EndElement handles the empty-content case
					if err := xml.EscapeText(&buf, []byte(proxied)); err != nil {
						return mpd
					}
					continue
				}
				// whitespace-only: keep inBaseURL=true so the real URL on the
				// next CharData token is still caught
			}
			buf.Write(raw)

		default:
			buf.Write(raw)
		}
	}

	if len(stack) != 0 {
		return mpd
	}
	buf.Write(mpd[prev:])
	return buf.Bytes()
}

// dashQName renders an element or attribute name as it appeared in the source
// (prefix:local) from a RawToken name, where Space holds the unresolved prefix.
func dashQName(n xml.Name) string {
	if n.Space == "" {
		return n.Local
	}
	return n.Space + ":" + n.Local
}
