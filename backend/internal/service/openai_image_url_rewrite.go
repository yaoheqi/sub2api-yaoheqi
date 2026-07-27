package service

import (
	"bytes"
	"encoding/json"
	"strings"
)

func rewriteOpenAIImageResponseURLs(body []byte, from, to string) []byte {
	from = strings.TrimRight(strings.TrimSpace(from), "/")
	to = strings.TrimRight(strings.TrimSpace(to), "/")
	if len(body) == 0 || from == "" || to == "" || from == to {
		return body
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var payload any
	if err := decoder.Decode(&payload); err != nil {
		return body
	}
	if !rewriteOpenAIImageURLValue(payload, from, to) {
		return body
	}
	rewritten, err := json.Marshal(payload)
	if err != nil {
		return body
	}
	return rewritten
}

func rewriteOpenAIImageURLValue(value any, from, to string) bool {
	changed := false
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if raw, ok := child.(string); ok && isOpenAIImageURLField(key) {
				if rewritten, ok := rewriteOpenAIImageURL(raw, from, to); ok {
					typed[key] = rewritten
					changed = true
				}
				continue
			}
			if rewriteOpenAIImageURLValue(child, from, to) {
				changed = true
			}
		}
	case []any:
		for _, child := range typed {
			if rewriteOpenAIImageURLValue(child, from, to) {
				changed = true
			}
		}
	}
	return changed
}

func isOpenAIImageURLField(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "url", "image_url":
		return true
	default:
		return false
	}
}

func rewriteOpenAIImageURL(raw, from, to string) (string, bool) {
	if raw == from {
		return to, true
	}
	if strings.HasPrefix(raw, from+"/") {
		return to + strings.TrimPrefix(raw, from), true
	}
	return raw, false
}

func rewriteOpenAIImageSSELine(line []byte, from, to string) []byte {
	if strings.TrimSpace(from) == "" || strings.TrimSpace(to) == "" {
		return line
	}
	ending := ""
	content := line
	if bytes.HasSuffix(content, []byte("\r\n")) {
		ending = "\r\n"
		content = content[:len(content)-2]
	} else if bytes.HasSuffix(content, []byte("\n")) {
		ending = "\n"
		content = content[:len(content)-1]
	}
	trimmed := bytes.TrimSpace(content)
	if !bytes.HasPrefix(trimmed, []byte("data:")) {
		return line
	}
	data := bytes.TrimSpace(bytes.TrimPrefix(trimmed, []byte("data:")))
	rewritten := rewriteOpenAIImageResponseURLs(data, from, to)
	if bytes.Equal(data, rewritten) {
		return line
	}
	return append(append([]byte("data: "), rewritten...), ending...)
}
