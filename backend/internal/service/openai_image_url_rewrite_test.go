package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRewriteOpenAIImageResponseURLs(t *testing.T) {
	body := []byte(`{"created":123,"data":[{"url":"http://108.160.143.150:6001/generated/a.png"},{"image_url":"http://108.160.143.150:6001/generated/b.png?x=1"},{"b64_json":"abc"}],"prompt":"http://108.160.143.150:6001/generated/do-not-rewrite.png"}`)
	got := rewriteOpenAIImageResponseURLs(body, "http://108.160.143.150:6001/", "https://yaoheqi.xyz/")
	require.JSONEq(t, `{"created":123,"data":[{"url":"https://yaoheqi.xyz/generated/a.png"},{"image_url":"https://yaoheqi.xyz/generated/b.png?x=1"},{"b64_json":"abc"}],"prompt":"http://108.160.143.150:6001/generated/do-not-rewrite.png"}`, string(got))
}

func TestRewriteOpenAIImageResponseURLsDoesNotMatchSimilarHost(t *testing.T) {
	body := []byte(`{"data":[{"url":"http://108.160.143.150:60010/generated/a.png"}]}`)
	require.Equal(t, body, rewriteOpenAIImageResponseURLs(body, "http://108.160.143.150:6001", "https://yaoheqi.xyz"))
}

func TestRewriteOpenAIImageSSELine(t *testing.T) {
	line := []byte("data: {\"data\":[{\"url\":\"http://108.160.143.150:6001/generated/a.png\"}]}\n")
	got := rewriteOpenAIImageSSELine(line, "http://108.160.143.150:6001", "https://yaoheqi.xyz")
	require.JSONEq(t, `{"data":[{"url":"https://yaoheqi.xyz/generated/a.png"}]}`, string(got[len("data: "):len(got)-1]))
}
