package openai

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDefaultModelsIncludeBareGPT56Alias(t *testing.T) {
	require.Contains(t, DefaultModelIDs(), "gpt-5.6")
	require.Contains(t, DefaultModelIDs(), "gpt-5.6-sol-wm")
}

func TestDefaultModelsPreferConcreteGPT56SolForAccountTests(t *testing.T) {
	require.NotEmpty(t, DefaultModels)
	require.Equal(t, "gpt-5.6-sol", DefaultModels[0].ID)
}

func TestCodexOAuthDefaultModels(t *testing.T) {
	ids := make([]string, 0, len(CodexOAuthDefaultModels))
	for _, model := range CodexOAuthDefaultModels {
		ids = append(ids, model.ID)
	}
	require.Equal(t, []string{"gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.5"}, ids)
}
