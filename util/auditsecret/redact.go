package auditsecret

import (
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/url"
	"strings"
)

const Mask = "***"
const Omitted = "[audit body omitted: unsupported or malformed encoding]"

func sensitive(key string) bool {
	key, err := url.QueryUnescape(key)
	if err != nil {
		return true
	}
	key = strings.ToLower(strings.NewReplacer("_", "", "-", "", " ", "").Replace(key))
	// Preserve both the production hotfix aliases and newer Casdoor credentials.
	if strings.Contains(key, "password") {
		return true
	}
	switch key {
	case "passwd", "pwd", "clientsecret", "accesssecret", "accesstoken", "refreshtoken",
		"idtoken", "idtokenhint", "authorization", "codeverifier", "passcode", "recoverycode":
		return true
	}
	return false
}

func redact(value interface{}) {
	switch v := value.(type) {
	case map[string]interface{}:
		for key, item := range v {
			if sensitive(key) {
				if items, ok := item.([]interface{}); ok {
					for i := range items {
						items[i] = Mask
					}
				} else {
					v[key] = Mask
				}
			} else {
				redact(item)
			}
		}
	case []interface{}:
		for _, item := range v {
			redact(item)
		}
	}
}

func encode(value interface{}) string {
	b, err := json.Marshal(value)
	if err != nil {
		return Omitted
	}
	return string(b)
}

// Body never returns an unparsed request body. Form bodies become JSON so the
// defensive pre-webhook pass can redact them again without their boundary.
func Body(body, contentType string) string {
	if body == "" {
		return ""
	}
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil && contentType != "" {
		return Omitted
	}
	switch mediaType {
	case "", "application/json":
		var value interface{}
		decoder := json.NewDecoder(strings.NewReader(body))
		decoder.UseNumber()
		if decoder.Decode(&value) != nil {
			return Omitted
		}
		var extra interface{}
		if decoder.Decode(&extra) != io.EOF {
			return Omitted
		}
		// API audit bodies have named fields; opaque JSON scalars cannot be safely classified.
		switch value.(type) {
		case map[string]interface{}, []interface{}:
		default:
			return Omitted
		}
		redact(value)
		return encode(value)
	case "application/x-www-form-urlencoded":
		values, err := url.ParseQuery(body)
		if err != nil {
			return Omitted
		}
		for key := range values {
			if sensitive(key) {
				values[key] = []string{Mask}
			}
		}
		return encode(values)
	case "multipart/form-data":
		if params["boundary"] == "" {
			return Omitted
		}
		reader := multipart.NewReader(strings.NewReader(body), params["boundary"])
		values := map[string][]string{}
		for {
			part, err := reader.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				return Omitted
			}
			key := part.FormName()
			if key == "" {
				return Omitted
			}
			if sensitive(key) || part.FileName() != "" {
				values[key] = append(values[key], Mask)
				if part.Close() != nil {
					return Omitted
				}
				continue
			}
			data, err := io.ReadAll(part)
			if err != nil {
				return Omitted
			}
			values[key] = append(values[key], string(data))
		}
		return encode(values)
	default:
		return Omitted
	}
}

func URI(raw string) string {
	u, err := url.ParseRequestURI(raw)
	if err != nil {
		return "[audit URI omitted]"
	}
	values, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return u.Path + "?[audit query omitted]"
	}
	for key := range values {
		if sensitive(key) {
			values[key] = []string{Mask}
		}
	}
	u.RawQuery = values.Encode()
	return u.String()
}
