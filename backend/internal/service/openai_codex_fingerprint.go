package service

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// codexFingerprintIDsContextKey 是暂存在 gin context 的收敛 ID 集合键。
// 由 Forward（非透传）或 forwardOpenAIPassthrough（透传）解析后写入，请求
// 构造器读取用于出站头改写——请求体与出站头必须共享同一份 IDs，保证
// turn_id 等随机字段一致。
const codexFingerprintIDsContextKey = "codex_fingerprint_ids"

// codexPrivacyAccountContextKey stores the credential account that owns the
// OAuth token for the current HTTP attempt. Spark shadow rows are routing and
// billing identities only; privacy pseudonyms and policy must be derived from
// the parent credential row so one token cannot expose two device identities.
const codexPrivacyAccountContextKey = "codex_privacy_account"

func stageCodexPrivacyAccount(c *gin.Context, account *Account) {
	if c != nil {
		c.Set(codexPrivacyAccountContextKey, account)
	}
}

func stagedCodexPrivacyAccount(c *gin.Context, fallback *Account) *Account {
	if c == nil {
		return fallback
	}
	value, ok := c.Get(codexPrivacyAccountContextKey)
	if !ok {
		return fallback
	}
	account, ok := value.(*Account)
	if !ok || account == nil {
		return fallback
	}
	return account
}

// resolveAndStageCodexPrivacyAccount resolves a Spark shadow to its parent for
// the duration of one HTTP attempt. The selected shadow itself remains the
// account used by scheduling, proxy selection, quota and usage accounting.
func (s *OpenAIGatewayService) resolveAndStageCodexPrivacyAccount(ctx context.Context, c *gin.Context, account *Account) (*Account, error) {
	if account == nil || !account.IsShadow() {
		stageCodexPrivacyAccount(c, account)
		return account, nil
	}
	if s == nil || s.accountRepo == nil {
		return nil, fmt.Errorf("resolve shadow privacy account: account repository is unavailable")
	}
	resolved, err := resolveCredentialAccount(ctx, s.accountRepo, account)
	if err != nil {
		return nil, err
	}
	stageCodexPrivacyAccount(c, resolved)
	return resolved, nil
}

// stageCodexFingerprintIDs 将本 attempt 解析出的收敛 ID 暂存到 gin context。
// 必须无条件覆写（含 nil）：failover 从收敛账号切到 off 账号时，上一账号的
// IDs 不得残留并被误应用到新账号的出站头（typed-nil 由应用侧 nil 守卫吸收）。
func stageCodexFingerprintIDs(c *gin.Context, ids *codexFingerprintIDs) {
	if c != nil {
		c.Set(codexFingerprintIDsContextKey, ids)
	}
}

func stagedCodexFingerprintIDs(c *gin.Context, account *Account) *codexFingerprintIDs {
	if c == nil || account == nil || account.Type != AccountTypeOAuth {
		return nil
	}
	value, ok := c.Get(codexFingerprintIDsContextKey)
	if !ok {
		return nil
	}
	ids, ok := value.(*codexFingerprintIDs)
	if !ok || ids == nil || ids.accountID != account.ID {
		return nil
	}
	return ids
}

// applyStagedCodexFingerprintHeaders 读取 context 暂存的收敛 ID 并改写出站头。
// 非透传与透传两个请求构造器共用本函数，防止应用语义漂移。仅解析该
// snapshot 的 OAuth 账号可读取，避免 stale context 跨账号 failover 泄漏。
func applyStagedCodexFingerprintHeaders(c *gin.Context, account *Account, h http.Header) {
	applyCodexFingerprintHeaders(h, stagedCodexFingerprintIDs(c, account))
}

func applyStagedCodexFingerprintClientMetadata(c *gin.Context, account *Account, reqBody map[string]any) bool {
	return applyCodexFingerprintClientMetadata(reqBody, stagedCodexFingerprintIDs(c, account))
}

// codexFingerprintMode 控制 OAuth 账号出站请求的设备指纹收敛强度。
// 多人共享同一 OAuth 账号时，每个用户的 Codex 客户端会携带各自不同的
// installation_id / session_id / thread_id，上游据此判定设备数和会话数。
// 收敛模式将这些标识改写为账号级恒定值，减少上游可见的设备/会话指纹。
type codexFingerprintMode string

const (
	// codexFingerprintOff 不做任何收敛，原样透传客户端标识。
	codexFingerprintOff codexFingerprintMode = "off"
	// codexFingerprintDevice 仅收敛 installation_id 为账号级恒定值。
	// 上游看到 1 台设备 + 多会话（每用户各自的 session）。
	codexFingerprintDevice codexFingerprintMode = "device"
	// codexFingerprintSession 收敛 installation_id + session_id，
	// thread_id 按客户端原始 session-id 确定性派生（每个真实 Codex 会话一个独立线程）。
	// 上游看到 1 台设备 + 1 会话 + N 线程，最接近正常用户 spawn 子代理的模式。
	codexFingerprintSession codexFingerprintMode = "session"
	// codexFingerprintFull 收敛所有标识：installation_id + session_id + thread_id。
	// 上游看到 1 台设备 + 1 会话 + 1 线程，最激进。
	codexFingerprintFull codexFingerprintMode = "full"
)

const (
	codexFingerprintModeExtraKey = "codex_fingerprint_mode"
	codexFingerprintSeedExtraKey = "codex_fingerprint_seed"
)

func canonicalCodexFingerprintSeed(value any) (string, bool) {
	raw, ok := value.(string)
	if !ok {
		return "", false
	}
	trimmed := strings.TrimSpace(raw)
	parsed, err := uuid.Parse(trimmed)
	if err != nil || parsed == uuid.Nil || trimmed != parsed.String() {
		return "", false
	}
	return trimmed, true
}

func newCodexFingerprintSeed() string {
	return uuid.NewString()
}

func stripCodexFingerprintSeed(extra map[string]any) map[string]any {
	if extra == nil {
		return nil
	}
	stripped := maps.Clone(extra)
	delete(stripped, codexFingerprintSeedExtraKey)
	return stripped
}

func codexFingerprintModeFromExtra(extra map[string]any) codexFingerprintMode {
	if extra == nil {
		return codexFingerprintSession
	}
	raw, _ := extra[codexFingerprintModeExtraKey].(string)
	switch codexFingerprintMode(strings.TrimSpace(raw)) {
	case codexFingerprintOff, codexFingerprintDevice, codexFingerprintSession, codexFingerprintFull:
		return codexFingerprintMode(strings.TrimSpace(raw))
	default:
		return codexFingerprintSession
	}
}

func codexFingerprintModeRequiresSeed(mode codexFingerprintMode) bool {
	switch mode {
	case codexFingerprintDevice, codexFingerprintSession, codexFingerprintFull:
		return true
	default:
		return false
	}
}

func codexFingerprintSeed(extra map[string]any) (string, bool) {
	if extra == nil {
		return "", false
	}
	return canonicalCodexFingerprintSeed(extra[codexFingerprintSeedExtraKey])
}

func prepareCodexFingerprintExtraForCreate(platform, accountType string, extra map[string]any) map[string]any {
	prepared := stripCodexFingerprintSeed(extra)
	if platform != PlatformOpenAI || accountType != AccountTypeOAuth {
		return prepared
	}
	mode := codexFingerprintModeFromExtra(prepared)
	if prepared == nil {
		prepared = make(map[string]any, 2)
	}
	// Persist the canonical default on newly-created OAuth accounts. Runtime
	// handling also treats missing/invalid values as session, but storing the
	// value makes the account's effective policy explicit and keeps future
	// default changes from silently altering it.
	prepared[codexFingerprintModeExtraKey] = string(mode)
	if !codexFingerprintModeRequiresSeed(mode) {
		return prepared
	}
	prepared[codexFingerprintSeedExtraKey] = newCodexFingerprintSeed()
	return prepared
}

func prepareCodexFingerprintExtraForUpdate(account *Account, extra map[string]any) map[string]any {
	prepared := stripCodexFingerprintSeed(extra)
	if account == nil || account.Platform != PlatformOpenAI || account.Type != AccountTypeOAuth {
		return prepared
	}
	if seed, ok := codexFingerprintSeed(account.Extra); ok {
		if prepared == nil {
			prepared = make(map[string]any, 1)
		}
		prepared[codexFingerprintSeedExtraKey] = seed
		return prepared
	}
	if codexFingerprintModeRequiresSeed(codexFingerprintModeFromExtra(prepared)) {
		if prepared == nil {
			prepared = make(map[string]any, 1)
		}
		prepared[codexFingerprintSeedExtraKey] = newCodexFingerprintSeed()
	}
	return prepared
}

func sanitizedCodexFingerprintExtraUpdates(updates map[string]any) map[string]any {
	if updates == nil {
		return nil
	}
	sanitized := maps.Clone(updates)
	delete(sanitized, codexFingerprintSeedExtraKey)
	return sanitized
}

// ShouldEnsureCodexFingerprintSeedForExtraUpdates reports whether a JSONB key-level
// extra update is enabling Codex fingerprint convergence and therefore must atomically
// preserve or create the system-managed per-account seed in the repository update.
func ShouldEnsureCodexFingerprintSeedForExtraUpdates(updates map[string]any) bool {
	if updates == nil {
		return false
	}
	// The repository method is shared by every account type and receives only
	// the JSONB delta, not the account row.  A missing mode key therefore cannot
	// mean "privacy OAuth default" here: treating it as session would make every
	// unrelated Extra update enter the Codex seed SQL path (including API-key
	// updates). OAuth lifecycle code explicitly supplies the mode when it needs
	// a managed seed; runtime defaults are handled without mutating other types.
	if _, ok := updates[codexFingerprintModeExtraKey]; !ok {
		return false
	}
	return codexFingerprintModeRequiresSeed(codexFingerprintModeFromExtra(updates))
}

// GetCodexFingerprintMode 从账号 extra JSON 读取指纹收敛模式。
//
// 未设置、空值或非法值按设备+会话（session）处理。显式配置的
// off / device / session / full 始终按管理员选择生效。
func (a *Account) GetCodexFingerprintMode() codexFingerprintMode {
	if a == nil || !a.IsOpenAIOAuth() {
		return codexFingerprintOff
	}
	return codexFingerprintModeFromExtra(a.Extra)
}

// deriveStableUUIDv4 从种子确定性派生一个 UUIDv4 格式的字符串。
// 同一种子永远返回同一值。
func deriveStableUUIDv4(seed string) string {
	h := sha256.Sum256([]byte(seed))
	b := h[:16]
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 1
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		binary.BigEndian.Uint32(b[0:4]),
		binary.BigEndian.Uint16(b[4:6]),
		binary.BigEndian.Uint16(b[6:8]),
		binary.BigEndian.Uint16(b[8:10]),
		b[10:16])
}

// deriveStableUUIDv7 keeps the deterministic behavior required by the
// compact probe while presenting the UUID version expected by Codex protocol
// identifiers. The timestamp bits are derived from the seed rather than from
// wall-clock time because probe sessions must remain stable across retries.
func deriveStableUUIDv7(seed string) string {
	h := sha256.Sum256([]byte(seed))
	b := h[:16]
	b[6] = (b[6] & 0x0f) | 0x70 // version 7
	b[8] = (b[8] & 0x3f) | 0x80 // variant 1
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		binary.BigEndian.Uint32(b[0:4]),
		binary.BigEndian.Uint16(b[4:6]),
		binary.BigEndian.Uint16(b[6:8]),
		binary.BigEndian.Uint16(b[8:10]),
		b[10:16])
}

var (
	codexFingerprintFallbackSecretOnce sync.Once
	codexFingerprintFallbackSecret     string
)

// codexFingerprintSecret 返回部署级派生密钥。
// 生产路径由数据库 bootstrap 注入；空值只在未初始化的单元测试/工具路径生成进程级
// 随机值，绝不使用公开常量或 account.ID 作为密钥。
func codexFingerprintSecret(configured ...string) string {
	for _, candidate := range configured {
		if value := strings.TrimSpace(candidate); value != "" {
			return value
		}
	}
	codexFingerprintFallbackSecretOnce.Do(func() {
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			// crypto/rand failure is exceptional; keep the process usable in tests
			// while still avoiding a fixed cross-deployment value.
			buf = []byte(uuid.New().String())
		}
		codexFingerprintFallbackSecret = hex.EncodeToString(buf)
	})
	return codexFingerprintFallbackSecret
}

// codexFingerprintSecretUsable is intentionally stricter than a non-empty
// check.  Production requests must use the shared, bootstrap-persisted
// deployment secret; a short/missing value would make replicas derive
// different pseudonyms or silently fall back to a process-local test secret.
func codexFingerprintSecretUsable(secret string) bool {
	return len([]byte(strings.TrimSpace(secret))) >= 32
}

// deriveDeploymentUUID uses a keyed, domain-separated digest. The deployment secret makes
// identical account IDs and client IDs produce different values in different installations.
func deriveDeploymentUUID(secret, domain string) string {
	mac := hmac.New(sha256.New, []byte(codexFingerprintSecret(secret)))
	_, _ = mac.Write([]byte("sub2api/codex-privacy/v2\x00" + domain))
	b := mac.Sum(nil)[:16]
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 1
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		binary.BigEndian.Uint32(b[0:4]),
		binary.BigEndian.Uint16(b[4:6]),
		binary.BigEndian.Uint16(b[6:8]),
		binary.BigEndian.Uint16(b[8:10]),
		b[10:16])
}

// resolveConvergedInstallationID returns an account-scoped pseudonym. The
// v178 per-account seed remains the lifecycle anchor; the deployment secret
// prevents identical seeds from being comparable across independent installs.
func resolveConvergedInstallationID(account *Account, seed string, deploymentSecret ...string) string {
	if account == nil || seed == "" {
		return ""
	}
	// The account ID is only an input namespace inside the deployment HMAC;
	// it is never sent upstream. Including it also prevents accidental
	// collisions if two rows are ever assigned the same seed.
	material := fmt.Sprintf("account:%d\nseed:%s", account.ID, seed)
	if deviceID := strings.TrimSpace(account.GetOpenAIDeviceID()); deviceID != "" {
		material += "\ndevice:" + deviceID
	}
	return deriveDeploymentUUID(codexFingerprintSecret(deploymentSecret...), "installation:"+material)
}

func resolveConvergedSessionID(seed string, deploymentSecret ...string) string {
	if seed == "" {
		return ""
	}
	return deriveDeploymentUUID(codexFingerprintSecret(deploymentSecret...), "session:seed:"+seed)
}

// resolveConvergedThreadID derives one stable pseudonym per client session.
func resolveConvergedThreadID(seed, clientSessionID string, deploymentSecret ...string) string {
	if seed == "" || clientSessionID == "" {
		return ""
	}
	return deriveDeploymentUUID(codexFingerprintSecret(deploymentSecret...), "thread:seed:"+seed+"\nclient-session:"+clientSessionID)
}

// codexFingerprintIDs 收敛后的完整 ID 集合。
// 由 resolveCodexFingerprintIDs 一次性生成，同一个实例在头改写和体改写之间共享，
// 确保所有载体中的 turn_id 等随机字段一致。体改写时还会补记原始
// client_metadata.session_id，用于识别 root prompt_cache_key 的默认值。
type codexFingerprintIDs struct {
	accountID                     int64
	mode                          codexFingerprintMode
	installationID                string
	sessionID                     string
	threadID                      string
	turnID                        string
	windowID                      string
	clientSessionID               string
	turnStartedAtUnixMs           int64
	originalBodySessionID         string
	originalBodySessionIDCaptured bool
	promptCacheKey                string
	promptCacheCanonical          string
	promptCacheMappings           map[string]string
	promptCacheGenerated          map[string]struct{}
	conversationMappings          map[string]string
	conversationGenerated         map[string]struct{}
}

// resolveCodexFingerprintIDs 按收敛模式计算出站 ID 集合。
// clientSessionID 是客户端原始的 session-id 头值（连字符形式），用于 session 模式下
// 的 thread_id 派生——每个真实 Codex 会话得到一个独立线程。
// 返回 nil 表示 off 模式，不需要改写。
// 注意：包含随机生成的 turn_id，调用方必须只调用一次并共享结果给头改写和体改写。
func resolveCodexFingerprintIDs(account *Account, clientSessionID string, mode codexFingerprintMode, deploymentSecret ...string) *codexFingerprintIDs {
	if account == nil || mode == codexFingerprintOff {
		return nil
	}
	secret := codexFingerprintSecret(deploymentSecret...)
	seed, ok := codexFingerprintSeed(account.Extra)
	if !ok {
		// v178 migration 225 only backfills explicitly enabled accounts. The
		// privacy default also covers legacy OAuth rows, so derive a temporary
		// deployment-bound seed instead of falling back to a raw account ID or
		// forwarding the client identity. Account updates persist the managed
		// per-account seed through the normal v178 lifecycle.
		seed = "fallback:" + deriveDeploymentToken(secret, "seed", fmt.Sprintf("account:%d", account.ID))
	}

	ids := &codexFingerprintIDs{
		accountID:             account.ID,
		mode:                  mode,
		clientSessionID:       clientSessionID,
		turnStartedAtUnixMs:   time.Now().UnixMilli(),
		promptCacheMappings:   make(map[string]string),
		promptCacheGenerated:  make(map[string]struct{}),
		conversationMappings:  make(map[string]string),
		conversationGenerated: make(map[string]struct{}),
	}

	ids.installationID = resolveConvergedInstallationID(account, seed, secret)
	if ids.installationID == "" {
		return nil
	}

	switch mode {
	case codexFingerprintDevice:
		return ids

	case codexFingerprintSession:
		ids.sessionID = resolveConvergedSessionID(seed, secret)
		ids.threadID = resolveConvergedThreadID(seed, clientSessionID, secret)
		if ids.threadID == "" {
			ids.threadID = ids.sessionID
		}
		ids.turnID = uuid.Must(uuid.NewV7()).String()
		ids.windowID = ids.threadID + ":0"
		return ids

	case codexFingerprintFull:
		ids.sessionID = resolveConvergedSessionID(seed, secret)
		ids.threadID = ids.sessionID
		ids.turnID = uuid.Must(uuid.NewV7()).String()
		ids.windowID = ids.threadID + ":0"
		return ids
	}

	return nil
}

// extractClientSessionID 从请求头中提取客户端原始的会话标识。
// 优先取 session-id（连字符形式，Codex CLI 标准），回退到 session_id（下划线形式）。
// 返回的值尚未被 isolateOpenAISessionID 改写，是客户端的真实标识。
func extractClientSessionID(h http.Header) string {
	if v := strings.TrimSpace(h.Get("session-id")); v != "" {
		return v
	}
	return strings.TrimSpace(h.Get("session_id"))
}

// resolveCodexFingerprintIDsFromRequest 从客户端原始请求头中提取 session-id，
// 结合账号配置一次性解析收敛 ID 集合。调用方应将返回的 ids 同时传给
// applyCodexFingerprintHeaders 和 applyCodexFingerprintClientMetadata。
func resolveCodexFingerprintIDsFromRequest(account *Account, clientHeaders http.Header, deploymentSecret ...string) *codexFingerprintIDs {
	if account == nil {
		return nil
	}
	mode := account.GetCodexFingerprintMode()
	if mode == codexFingerprintOff {
		return nil
	}
	// A supplied (including empty) secret means the caller is a production
	// gateway path.  Do not let it silently use the process-local test fallback.
	if len(deploymentSecret) > 0 && strings.TrimSpace(deploymentSecret[0]) == "" {
		return nil
	}
	clientSessionID := ""
	if clientHeaders != nil {
		clientSessionID = extractClientSessionID(clientHeaders)
	}
	return resolveCodexFingerprintIDs(account, clientSessionID, mode, deploymentSecret...)
}

// resolveGatewayCodexFingerprintIDs uses the deployment JWT secret as the
// HMAC namespace for production requests. This keeps the account pseudonyms
// stable across process restarts and consistent across gateway replicas.
// Unit/test services without a configured JWT secret retain the process-local
// fallback used by the low-level helpers.
func (s *OpenAIGatewayService) resolveGatewayCodexFingerprintIDs(account *Account, clientHeaders http.Header) *codexFingerprintIDs {
	secret := ""
	if s != nil && s.cfg != nil {
		secret = strings.TrimSpace(s.cfg.JWT.Secret)
	}
	if codexFingerprintSecretUsable(secret) {
		return resolveCodexFingerprintIDsFromRequest(account, clientHeaders, secret)
	}
	return resolveCodexFingerprintIDsFromRequest(account, clientHeaders)
}

// applyCodexFingerprintHeaders 按预计算的收敛 ID 改写出站 HTTP 头中的设备指纹。
// 在 buildUpstreamRequest 的白名单透传之后、enforceCodexIdentityHeaders 之前调用。
func applyCodexFingerprintHeaders(h http.Header, ids *codexFingerprintIDs) {
	if h == nil || ids == nil {
		return
	}

	// 所有非 off 模式都收敛 installation_id
	h.Set("x-codex-installation-id", ids.installationID)

	if ids.mode == codexFingerprintDevice {
		rewriteCodexTurnMetadataFields(h, map[string]any{
			"installation_id": ids.installationID,
		})
		return
	}

	// session / full 模式：改写所有相关头
	h.Set("x-codex-window-id", ids.windowID)
	h.Set("x-client-request-id", ids.threadID)
	// 连字符形式和下划线形式都改写，保证一致
	h.Set("session-id", ids.sessionID)
	h.Set("session_id", ids.sessionID)
	h.Set("thread-id", ids.threadID)

	rewriteCodexTurnMetadataFields(h, map[string]any{
		"installation_id":         ids.installationID,
		"session_id":              ids.sessionID,
		"thread_id":               ids.threadID,
		"turn_id":                 ids.turnID,
		"window_id":               ids.windowID,
		"turn_started_at_unix_ms": ids.turnStartedAtUnixMs,
	})
}

// rewriteCodexTurnMetadataFields 解析 x-codex-turn-metadata 头中的 JSON，
// 替换指定字段后回写。合法对象保留未指定字段（如 sandbox、thread_source）；
// 非法/非对象值重建为最小合法 metadata，避免 flat 与 embedded identity 分裂。
func rewriteCodexTurnMetadataFields(h http.Header, fields map[string]any) {
	raw := strings.TrimSpace(h.Get("x-codex-turn-metadata"))
	if raw == "" {
		return
	}
	var metadata map[string]any
	if err := json.Unmarshal([]byte(raw), &metadata); err != nil || metadata == nil {
		metadata = make(map[string]any, len(fields))
	}
	for k, v := range fields {
		metadata[k] = v
	}
	rebuilt, err := json.Marshal(metadata)
	if err != nil {
		return
	}
	h.Set("x-codex-turn-metadata", string(rebuilt))
}

// applyCodexFingerprintClientMetadata 按预计算的收敛 ID 改写请求体中的 client_metadata。
// 使用与头改写相同的 ids 实例，确保 turn_id 等随机字段一致。
func applyCodexFingerprintClientMetadata(reqBody map[string]any, ids *codexFingerprintIDs) bool {
	if reqBody == nil || ids == nil {
		return false
	}

	captureCodexFingerprintOriginalBodySessionID(ids, reqBody["client_metadata"])
	existing, _ := reqBody["client_metadata"].(map[string]any)
	if existing == nil {
		existing = make(map[string]any)
	}

	modified := false
	if applyCodexFingerprintToClientMetadataMap(existing, ids) {
		reqBody["client_metadata"] = existing
		modified = true
	}
	if applyCodexFingerprintPromptCacheKey(reqBody, ids) {
		modified = true
	}
	return modified
}

// applyCodexFingerprintToClientMetadataMap 是 client_metadata 改写的共享核心，
// map 版（非透传，body 已解码）与 raw 字节版（透传热路径）都经由它，保证两条
// 路径的收敛语义永不漂移。
func applyCodexFingerprintToClientMetadataMap(existing map[string]any, ids *codexFingerprintIDs) bool {
	if existing == nil || ids == nil {
		return false
	}

	modified := false

	if ids.installationID != "" {
		existing["x-codex-installation-id"] = ids.installationID
		modified = true
	}

	if ids.mode == codexFingerprintDevice {
		rewriteClientMetadataEmbeddedTurnMetadata(existing, map[string]any{
			"installation_id": ids.installationID,
		})
		return modified
	}

	// session / full 模式
	existing["session_id"] = ids.sessionID
	existing["thread_id"] = ids.threadID
	existing["turn_id"] = ids.turnID
	existing["x-codex-window-id"] = ids.windowID

	rewriteClientMetadataEmbeddedTurnMetadata(existing, map[string]any{
		"installation_id":         ids.installationID,
		"session_id":              ids.sessionID,
		"thread_id":               ids.threadID,
		"turn_id":                 ids.turnID,
		"window_id":               ids.windowID,
		"turn_started_at_unix_ms": ids.turnStartedAtUnixMs,
	})
	return true
}

func captureCodexFingerprintOriginalBodySessionID(ids *codexFingerprintIDs, clientMetadata any) {
	if ids == nil || ids.originalBodySessionIDCaptured {
		return
	}
	ids.originalBodySessionIDCaptured = true
	if clientMetadata == nil {
		return
	}
	switch metadata := clientMetadata.(type) {
	case map[string]any:
		if sessionID, ok := metadata["session_id"].(string); ok {
			ids.originalBodySessionID = strings.TrimSpace(sessionID)
		}
	case map[string]string:
		ids.originalBodySessionID = strings.TrimSpace(metadata["session_id"])
	}
}

func captureCodexFingerprintOriginalBodySessionIDRaw(ids *codexFingerprintIDs, value gjson.Result) {
	if ids == nil || ids.originalBodySessionIDCaptured {
		return
	}
	ids.originalBodySessionIDCaptured = true
	if value.Exists() && value.Type == gjson.String {
		ids.originalBodySessionID = strings.TrimSpace(value.String())
	}
}

func shouldRewriteCodexFingerprintPromptCacheKey(ids *codexFingerprintIDs, promptCacheKey string) bool {
	if ids == nil || !ids.originalBodySessionIDCaptured || ids.originalBodySessionID == "" || ids.sessionID == "" {
		return false
	}
	if ids.mode != codexFingerprintSession && ids.mode != codexFingerprintFull {
		return false
	}
	return promptCacheKey == ids.originalBodySessionID
}

func applyCodexFingerprintPromptCacheKey(reqBody map[string]any, ids *codexFingerprintIDs) bool {
	if reqBody == nil {
		return false
	}
	promptCacheKey, ok := reqBody["prompt_cache_key"].(string)
	if !ok || strings.TrimSpace(promptCacheKey) == "" || !shouldRewriteCodexFingerprintPromptCacheKey(ids, promptCacheKey) {
		return false
	}
	if promptCacheKey == ids.sessionID {
		return false
	}
	reqBody["prompt_cache_key"] = ids.sessionID
	return true
}

// applyCodexFingerprintClientMetadataRaw 在原始 JSON 字节上改写 client_metadata，
// 供透传路径使用——透传是热路径，禁止对可能高达数十 MB 的 body 做全量
// Unmarshal（见 forwardOpenAIPassthrough 的轻量提取注释）。实现为：gjson 提取
// client_metadata 小对象单独解码，经共享核心改写后 sjson 一次性拼回，body
// 其余字节原样保留；root prompt_cache_key 仅在可证明是 body session 默认值时
// 做标量改写。语义与 applyCodexFingerprintClientMetadata 逐点一致（含
// "非对象值整体替换为收敛集合"的行为）。
func applyCodexFingerprintClientMetadataRaw(body []byte, ids *codexFingerprintIDs) ([]byte, bool, error) {
	if len(body) == 0 || ids == nil {
		return body, false, nil
	}
	// 非 JSON 对象的 body（数组/标量/畸形）没有 client_metadata 语义，
	// sjson 在这类根上写字段会改写整体结构，直接放行保持原样。
	root := gjson.ParseBytes(body)
	if !root.IsObject() {
		captureCodexFingerprintOriginalBodySessionIDRaw(ids, gjson.Result{})
		return body, false, nil
	}

	existing := map[string]any{}
	if cm := gjson.GetBytes(body, "client_metadata"); cm.IsObject() {
		captureCodexFingerprintOriginalBodySessionIDRaw(ids, gjson.GetBytes(body, "client_metadata.session_id"))
		if err := json.Unmarshal([]byte(cm.Raw), &existing); err != nil {
			return body, false, fmt.Errorf("decode client_metadata for fingerprint: %w", err)
		}
	} else {
		captureCodexFingerprintOriginalBodySessionIDRaw(ids, gjson.Result{})
	}

	next := body
	modified := false
	if applyCodexFingerprintToClientMetadataMap(existing, ids) {
		raw, err := json.Marshal(existing)
		if err != nil {
			return body, false, fmt.Errorf("encode converged client_metadata: %w", err)
		}
		var setErr error
		next, setErr = sjson.SetRawBytes(body, "client_metadata", raw)
		if setErr != nil {
			return body, false, fmt.Errorf("splice converged client_metadata: %w", setErr)
		}
		modified = true
	}
	promptCacheKey := gjson.GetBytes(body, "prompt_cache_key")
	if promptCacheKey.Exists() && promptCacheKey.Type == gjson.String && strings.TrimSpace(promptCacheKey.String()) != "" && shouldRewriteCodexFingerprintPromptCacheKey(ids, promptCacheKey.String()) {
		rewritten, err := sjson.SetBytes(next, "prompt_cache_key", ids.sessionID)
		if err != nil {
			return body, false, fmt.Errorf("splice converged prompt_cache_key: %w", err)
		}
		next = rewritten
		modified = true
	}
	return next, modified, nil
}

// rewriteClientMetadataEmbeddedTurnMetadata 改写 client_metadata 中内嵌的
// x-codex-turn-metadata JSON 字符串里的指定字段。非法/非对象值会重建，
// 避免 flat client_metadata 与 embedded metadata 暴露两套身份。
func rewriteClientMetadataEmbeddedTurnMetadata(clientMetadata map[string]any, fields map[string]any) {
	raw, ok := clientMetadata["x-codex-turn-metadata"].(string)
	if !ok || raw == "" {
		return
	}
	var metadata map[string]any
	if err := json.Unmarshal([]byte(raw), &metadata); err != nil || metadata == nil {
		metadata = make(map[string]any, len(fields))
	}
	for k, v := range fields {
		metadata[k] = v
	}
	if rebuilt, err := json.Marshal(metadata); err == nil {
		clientMetadata["x-codex-turn-metadata"] = string(rebuilt)
	}
}

// codexPrivacyEnabled is deliberately tied to OAuth/Codex accounts. API-key
// accounts do not use the ChatGPT device/session contract; their arbitrary
// application metadata must be governed by the platform-specific policy rather
// than silently rewritten as if it were a Codex client.
func codexPrivacyEnabled(account *Account) bool {
	if account == nil || !account.IsOpenAIOAuth() {
		return false
	}
	// A Spark shadow does not own credentials or an independent privacy
	// policy. Keep its data-plane behavior fail-closed even if a stale/manual
	// row contains codex_fingerprint_mode=off; the request-level privacy source
	// is resolved to the parent before identity derivation.
	if account.IsShadow() {
		return true
	}
	return account.GetCodexFingerprintMode() != codexFingerprintOff
}

// codexPrivacyCapabilityError is used at protocol boundaries for endpoints whose
// payload is opaque or whose implementation does not share the Responses
// sanitizer. Returning an explicit error is safer than forwarding a partly
// sanitized request and claiming that the privacy policy covers it.
func codexPrivacyCapabilityError(capability string) error {
	capability = strings.TrimSpace(capability)
	if capability == "" {
		capability = "this endpoint"
	}
	return fmt.Errorf("%s is disabled for privacy-enabled OAuth accounts; use the HTTP Responses endpoint", capability)
}

// codexPrivacyBodyMarker is safe for operational context fields. Privacy
// accounts never place an upstream body (which may echo client metadata) in
// logs or Ops state; non-privacy accounts retain the existing bounded detail.
func codexPrivacyBodyMarker(account *Account, body []byte, limit int) string {
	if !codexPrivacyEnabled(account) {
		if limit <= 0 {
			limit = 2048
		}
		return truncateString(string(body), limit)
	}
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:8])
}

func codexPrivacyUpstreamMessage(account *Account, statusCode int, message string) string {
	if !codexPrivacyEnabled(account) {
		return message
	}
	message = strings.TrimSpace(message)
	if message == "" {
		return fmt.Sprintf("OpenAI upstream error (status=%d)", statusCode)
	}
	return fmt.Sprintf(
		"OpenAI upstream error (status=%d, message_%s)",
		statusCode,
		hashSensitiveValueForLog(message),
	)
}

func codexPrivacyUpstreamErrorBody(account *Account, statusCode int, body []byte) []byte {
	if !codexPrivacyEnabled(account) {
		return body
	}
	safe, err := json.Marshal(map[string]any{
		"error": map[string]any{
			"type":    "upstream_error",
			"message": codexPrivacyUpstreamMessage(account, statusCode, extractUpstreamErrorMessage(body)),
		},
	})
	if err != nil {
		return []byte(`{"error":{"type":"upstream_error","message":"OpenAI upstream error"}}`)
	}
	return safe
}

func (s *OpenAIGatewayService) codexPrivacyUpstreamErrorDetail(account *Account, body []byte) string {
	if codexPrivacyEnabled(account) || s == nil || s.cfg == nil || !s.cfg.Gateway.LogUpstreamErrorBody {
		return ""
	}
	limit := s.cfg.Gateway.LogUpstreamErrorBodyMaxBytes
	if limit <= 0 {
		limit = 2048
	}
	return truncateString(string(body), limit)
}

// stagedCodexFingerprintIDsForAccount returns only a snapshot minted for the
// currently selected account. The context is shared by retries and failover,
// so account identity is an explicit part of the lookup rather than an
// implicit assumption.
func stagedCodexFingerprintIDsForAccount(c *gin.Context, account *Account) *codexFingerprintIDs {
	if c == nil || account == nil {
		return nil
	}
	value, ok := c.Get(codexFingerprintIDsContextKey)
	if !ok {
		return nil
	}
	ids, ok := value.(*codexFingerprintIDs)
	if !ok || ids == nil {
		return nil
	}
	if ids.accountID != 0 && ids.accountID != account.ID {
		return nil
	}
	return ids
}

// ensureStagedCodexFingerprintIDs creates the request-scoped snapshot when a
// route (notably compact/passthrough) reaches the request builder without
// having passed through the normal Forward staging block.
func ensureStagedCodexFingerprintIDs(c *gin.Context, account *Account, secret string) *codexFingerprintIDs {
	if !codexPrivacyEnabled(account) {
		stageCodexFingerprintIDs(c, nil)
		return nil
	}
	if ids := stagedCodexFingerprintIDsForAccount(c, account); ids != nil {
		return ids
	}
	var headers http.Header
	if c != nil && c.Request != nil {
		headers = c.Request.Header
	}
	ids := resolveCodexFingerprintIDsFromRequest(account, headers, secret)
	stageCodexFingerprintIDs(c, ids)
	return ids
}

// deriveDeploymentToken is used for values that are not required to have UUID
// syntax (for example a caller supplied prompt_cache_key). The raw input is
// never returned and independent deployments cannot produce the same token
// without intentionally sharing their secret.
func deriveDeploymentToken(secret, domain, raw string) string {
	mac := hmac.New(sha256.New, []byte(codexFingerprintSecret(secret)))
	_, _ = mac.Write([]byte("sub2api/codex-privacy/token/v2\x00" + domain + "\x00" + raw))
	return hex.EncodeToString(mac.Sum(nil)[:16])
}

func codexPrivacyPromptCacheKey(account *Account, ids *codexFingerprintIDs, secret, raw string) string {
	raw = strings.TrimSpace(raw)
	if ids == nil {
		return ""
	}
	if ids.promptCacheMappings == nil {
		ids.promptCacheMappings = make(map[string]string)
	}
	if ids.promptCacheGenerated == nil {
		ids.promptCacheGenerated = make(map[string]struct{})
	}
	if raw == "" || raw == ids.clientSessionID || raw == ids.sessionID {
		// A session-shaped cache key is already the canonical gateway identity.
		// Record it in the request snapshot so later nested carriers and the
		// header finalizer cannot select a different canonical value.
		canonical := ids.sessionID
		if canonical != "" {
			ids.promptCacheCanonical = canonical
			ids.promptCacheKey = canonical
			ids.promptCacheGenerated[canonical] = struct{}{}
			ids.promptCacheMappings[raw] = canonical
		}
		return canonical
	}
	// Idempotence is scoped to this request snapshot, never to a client
	// controlled prefix. A generated canonical value is accepted only if this
	// snapshot minted it; a caller-supplied string with the same shape is still
	// treated as a fresh input.
	if mapped, ok := ids.promptCacheMappings[raw]; ok {
		return mapped
	}
	if _, ok := ids.promptCacheGenerated[raw]; ok {
		return raw
	}
	if ids.promptCacheCanonical != "" {
		ids.promptCacheMappings[raw] = ids.promptCacheCanonical
		return ids.promptCacheCanonical
	}
	accountID := int64(0)
	if account != nil {
		accountID = account.ID
	}
	generated := "sub2api-cache-v2-" + deriveDeploymentToken(secret, fmt.Sprintf("account:%d", accountID), raw)
	ids.promptCacheMappings[raw] = generated
	ids.promptCacheGenerated[generated] = struct{}{}
	ids.promptCacheCanonical = generated
	ids.promptCacheKey = generated
	return generated
}

// codexPrivacyConversationID maps conversation identifiers once per request
// snapshot. The generated-value set makes the final header invariant
// idempotent when a compatibility builder invokes it more than once.
func codexPrivacyConversationID(account *Account, ids *codexFingerprintIDs, secret, raw string) string {
	raw = strings.TrimSpace(raw)
	if ids == nil || raw == "" {
		return ""
	}
	if raw == ids.sessionID || raw == ids.clientSessionID {
		return ids.sessionID
	}
	if ids.conversationMappings == nil {
		ids.conversationMappings = make(map[string]string)
	}
	if ids.conversationGenerated == nil {
		ids.conversationGenerated = make(map[string]struct{})
	}
	if mapped, ok := ids.conversationMappings[raw]; ok {
		return mapped
	}
	if _, ok := ids.conversationGenerated[raw]; ok {
		return raw
	}
	accountID := int64(0)
	if account != nil {
		accountID = account.ID
	}
	mapped := deriveDeploymentUUID(secret, fmt.Sprintf("conversation:account:%d:%s", accountID, raw))
	ids.conversationMappings[raw] = mapped
	ids.conversationGenerated[mapped] = struct{}{}
	return mapped
}

var codexPrivacyMetadataProtocolKeys = map[string]struct{}{
	"request_kind":    {},
	"streaming":       {},
	"sandbox":         {},
	"sandbox_mode":    {},
	"approval_policy": {},
	"network_access":  {},
	"reasoning_juice": {},
	"ws_request_header_x_openai_internal_codex_responses_lite": {},
	"x_openai_internal_codex_responses_lite":                   {},
	"responses_lite":                                           {},
}

func normalizeCodexPrivacyKey(key string) string {
	key = strings.TrimSpace(key)
	// JSON producers commonly spell these protocol carriers in camelCase.
	// Normalize known acronym forms before the generic boundary splitter so
	// `responsesAPIMetadata` cannot become an uninspected alias.
	switch strings.ToLower(key) {
	case "clientmetadata":
		return "client_metadata"
	case "promptcachekey":
		return "prompt_cache_key"
	case "responsesapimetadata", "responses_api_metadata":
		return "responsesapi_client_metadata"
	case "responsesapiclientmetadata", "responses_api_client_metadata":
		return "responsesapi_client_metadata"
	case "xcodexturnmetadata":
		return "x_codex_turn_metadata"
	case "conversationid":
		return "conversation_id"
	case "previousresponseid":
		return "previous_response_id"
	case "sessionid":
		return "session_id"
	case "threadid":
		return "thread_id"
	case "turnid":
		return "turn_id"
	case "windowid":
		return "window_id"
	case "installationid":
		return "installation_id"
	case "deviceid":
		return "device_id"
	case "xclientrequestid":
		return "x_client_request_id"
	}
	var normalized strings.Builder
	runes := []rune(key)
	for i, r := range runes {
		if unicode.IsUpper(r) && i > 0 {
			previous := runes[i-1]
			var next rune
			if i+1 < len(runes) {
				next = runes[i+1]
			}
			// Split lower->upper transitions and the final capital of an
			// acronym before a normal word (e.g. deviceID and
			// responsesAPIClientMetadata).  Tracking the original case avoids
			// turning an acronym such as ID into i_d.
			if unicode.IsLower(previous) || unicode.IsDigit(previous) ||
				(unicode.IsUpper(previous) && unicode.IsLower(next)) {
				normalized.WriteByte('_')
			}
		}
		normalized.WriteRune(unicode.ToLower(r))
	}
	key = normalized.String()
	key = strings.ReplaceAll(key, "-", "_")
	key = strings.ReplaceAll(key, ".", "_")
	return key
}

func isCodexPrivacyIdentityKey(key string) bool {
	switch normalizeCodexPrivacyKey(key) {
	case "installation_id", "x_codex_installation_id", "device_id":
		return true
	default:
		return false
	}
}

func isCodexPrivacySessionKey(key string) bool {
	switch normalizeCodexPrivacyKey(key) {
	case "session_id", "session":
		return true
	default:
		return false
	}
}

func isCodexPrivacyThreadKey(key string) bool {
	switch normalizeCodexPrivacyKey(key) {
	case "thread_id", "thread", "x_client_request_id":
		return true
	default:
		return false
	}
}

func isCodexPrivacyTurnKey(key string) bool {
	switch normalizeCodexPrivacyKey(key) {
	case "turn_id", "turn":
		return true
	default:
		return false
	}
}

func isCodexPrivacyWindowKey(key string) bool {
	switch normalizeCodexPrivacyKey(key) {
	case "window_id", "x_codex_window_id", "window":
		return true
	default:
		return false
	}
}

func isCodexPrivacyLineageKey(key string) bool {
	key = normalizeCodexPrivacyKey(key)
	return strings.Contains(key, "parent_") ||
		strings.Contains(key, "root_") ||
		strings.Contains(key, "fork") ||
		strings.Contains(key, "lineage")
}

func isCodexPrivacySensitiveMetadataKey(key string) bool {
	key = normalizeCodexPrivacyKey(key)
	for _, part := range []string{
		"workspace", "cwd", "path", "git", "remote", "commit", "dirty", "fingerprint",
		"hostname", "host_name", "user_home", "home_dir",
		"terminal", "plugin", "skill", "hook", "mcp", "trace", "span", "request_start",
		"tool_name", "server_name", "script", "device_kind", "agent_runtime", "task_id",
	} {
		if strings.Contains(key, part) {
			return true
		}
	}
	switch key {
	case "os", "arch", "platform", "operating_system", "cpu_architecture":
		return true
	}
	return false
}

func isCodexPrivacyMetadataProtocolKey(key string) bool {
	_, ok := codexPrivacyMetadataProtocolKeys[normalizeCodexPrivacyKey(key)]
	return ok
}

// sanitizeCodexPrivacyMetadataMap applies a strict allowlist only inside
// client/turn metadata containers. It intentionally does not walk input,
// tools, instructions, or output: those are model business data and cannot be
// safely deleted without changing the user's request.
func sanitizeCodexPrivacyMetadataMap(metadata map[string]any, ids *codexFingerprintIDs, account *Account, secret string, depth int) {
	if metadata == nil || ids == nil {
		return
	}
	if depth > 8 {
		// Callers cannot safely represent a partially sanitized nested carrier.
		// The parent helper removes the carrier when this sentinel is returned.
		for key := range metadata {
			delete(metadata, key)
		}
		return
	}
	for key, value := range metadata {
		normalized := normalizeCodexPrivacyKey(key)
		switch {
		case isCodexPrivacyIdentityKey(key):
			metadata[key] = ids.installationID
		case isCodexPrivacySessionKey(key):
			if ids.sessionID == "" {
				delete(metadata, key)
			} else {
				metadata[key] = ids.sessionID
			}
		case isCodexPrivacyThreadKey(key):
			if ids.threadID == "" {
				delete(metadata, key)
			} else {
				metadata[key] = ids.threadID
			}
		case isCodexPrivacyTurnKey(key):
			if ids.turnID == "" {
				delete(metadata, key)
			} else {
				metadata[key] = ids.turnID
			}
		case isCodexPrivacyWindowKey(key):
			if ids.windowID == "" {
				delete(metadata, key)
			} else {
				metadata[key] = ids.windowID
			}
		case normalized == "prompt_cache_key":
			if raw, ok := value.(string); ok {
				metadata[key] = codexPrivacyPromptCacheKey(account, ids, secret, raw)
			} else {
				delete(metadata, key)
			}
		case normalized == "turn_started_at_unix_ms":
			metadata[key] = ids.turnStartedAtUnixMs
		case normalized == "thread_source" || normalized == "subagent_kind" || normalized == "agent_name":
			metadata[key] = "gateway"
		case isCodexPrivacyLineageKey(key) || isCodexPrivacySensitiveMetadataKey(key):
			// Opaque lineage and environment values cannot be safely mapped at
			// this boundary. Dropping is fail-closed and avoids raw fallback.
			delete(metadata, key)
		case normalized == "x_codex_turn_metadata" || normalized == "responsesapi_client_metadata":
			// Only the canonical snake_case carrier names are allowed to leave
			// the gateway.  CamelCase/dotted aliases are still inspected below
			// when they are encountered, but are then dropped rather than being
			// retained as a second, stable metadata label.
			if normalized == "responsesapi_client_metadata" && key != normalized {
				delete(metadata, key)
				continue
			}
			sanitizeCodexPrivacyNestedMetadataValue(metadata, key, value, ids, account, secret, depth+1)
		case isCodexPrivacyMetadataProtocolKey(key):
			// These are optional client-reported execution/policy values. Their
			// syntactically safe forms can still be stable device labels (for
			// example sandbox="device_abc"). The gateway derives protocol state
			// itself, so strict privacy drops the client carrier altogether.
			delete(metadata, key)
		default:
			// Unknown optional metadata is not forwarded in strict mode. This
			// is deliberately narrower than a root-body allowlist.
			delete(metadata, key)
		}
	}
	metadata["x-codex-installation-id"] = ids.installationID
	if ids.sessionID != "" {
		metadata["session_id"] = ids.sessionID
	}
	if ids.threadID != "" {
		metadata["thread_id"] = ids.threadID
	}
	if ids.turnID != "" {
		metadata["turn_id"] = ids.turnID
	}
	if ids.windowID != "" {
		metadata["x-codex-window-id"] = ids.windowID
	}
}

func sanitizeCodexPrivacyNestedMetadataValue(metadata map[string]any, key string, value any, ids *codexFingerprintIDs, account *Account, secret string, depth int) {
	if depth > 8 {
		delete(metadata, key)
		return
	}
	switch typed := value.(type) {
	case map[string]any:
		if depth >= 8 {
			delete(metadata, key)
			return
		}
		sanitizeCodexPrivacyMetadataMap(typed, ids, account, secret, depth)
	case string:
		if depth >= 8 {
			delete(metadata, key)
			return
		}
		var nested map[string]any
		if err := json.Unmarshal([]byte(typed), &nested); err != nil || nested == nil {
			delete(metadata, key)
			return
		}
		sanitizeCodexPrivacyMetadataMap(nested, ids, account, secret, depth)
		if rebuilt, err := json.Marshal(nested); err == nil {
			metadata[key] = string(rebuilt)
		} else {
			delete(metadata, key)
		}
	case []any:
		if depth >= 8 {
			delete(metadata, key)
			return
		}
		for i := len(typed) - 1; i >= 0; i-- {
			nested, ok := typed[i].(map[string]any)
			if !ok {
				// Protocol metadata arrays must contain objects. Keeping an
				// unknown scalar would provide an uninspectable raw channel.
				typed = append(typed[:i], typed[i+1:]...)
				continue
			}
			sanitizeCodexPrivacyMetadataMap(nested, ids, account, secret, depth+1)
		}
		metadata[key] = typed
	default:
		// A protocol key with an unexpected scalar/object type is not
		// forwarded in strict mode; retaining it could hide an opaque value.
		delete(metadata, key)
	}
}

// sanitizeCodexPrivacyProtocolScalar retains only bounded, non-identifying
// protocol enum values. These keys are not JSON carriers and must not be sent
// through the nested-object validator (which would incorrectly delete valid
// values such as sandbox="seatbelt").
func sanitizeCodexPrivacyProtocolScalar(metadata map[string]any, key string, value any) bool {
	normalized := normalizeCodexPrivacyKey(key)
	if normalized == "streaming" || normalized == "responses_lite" ||
		normalized == "ws_request_header_x_openai_internal_codex_responses_lite" ||
		normalized == "x_openai_internal_codex_responses_lite" {
		switch typed := value.(type) {
		case bool:
			metadata[key] = typed
			return true
		case string:
			lower := strings.ToLower(strings.TrimSpace(typed))
			if lower == "true" || lower == "false" {
				metadata[key] = lower == "true"
				return true
			}
		}
		delete(metadata, key)
		return true
	}

	s, ok := value.(string)
	if !ok {
		delete(metadata, key)
		return true
	}
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 128 || !isCodexPrivacySafeEnum(s) {
		delete(metadata, key)
		return true
	}
	metadata[key] = s
	return true
}

func isCodexPrivacySafeEnum(value string) bool {
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' || r == ':' {
			continue
		}
		return false
	}
	return true
}

func findCodexPrivacyPromptCacheKey(value any, depth int) string {
	if depth > 8 {
		return ""
	}
	switch typed := value.(type) {
	case map[string]any:
		if raw, ok := typed["prompt_cache_key"].(string); ok && strings.TrimSpace(raw) != "" {
			return raw
		}
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if key == "prompt_cache_key" || normalizeCodexPrivacyKey(key) != "prompt_cache_key" {
				continue
			}
			if raw, ok := typed[key].(string); ok && strings.TrimSpace(raw) != "" {
				return raw
			}
		}
		for _, carrier := range []string{
			"client_metadata", "metadata", "x_codex_turn_metadata", "responsesapi_client_metadata",
		} {
			for _, key := range keys {
				if normalizeCodexPrivacyKey(key) != carrier {
					continue
				}
				if raw := findCodexPrivacyPromptCacheKey(typed[key], depth+1); raw != "" {
					return raw
				}
			}
		}
	case string:
		var decoded any
		if json.Unmarshal([]byte(typed), &decoded) == nil {
			return findCodexPrivacyPromptCacheKey(decoded, depth+1)
		}
	case []any:
		for _, item := range typed {
			if raw := findCodexPrivacyPromptCacheKey(item, depth+1); raw != "" {
				return raw
			}
		}
	}
	return ""
}

func primeCodexPrivacyPromptCacheCanonical(root map[string]any, account *Account, ids *codexFingerprintIDs, secret string) {
	if root == nil || ids == nil || ids.promptCacheCanonical != "" {
		return
	}
	if raw := findCodexPrivacyPromptCacheKey(root, 0); raw != "" {
		_ = codexPrivacyPromptCacheKey(account, ids, secret, raw)
	}
}

func sanitizeCodexPrivacyRequestBody(body []byte, account *Account, ids *codexFingerprintIDs, secret string) ([]byte, error) {
	if !codexPrivacyEnabled(account) {
		return body, nil
	}
	if ids == nil {
		return nil, fmt.Errorf("strict Codex privacy policy has no identity snapshot")
	}
	if strings.TrimSpace(secret) == "" {
		return nil, fmt.Errorf("strict Codex privacy policy has no valid deployment secret")
	}
	if len(body) == 0 || len(body) > 32<<20 {
		return nil, fmt.Errorf("strict Codex privacy policy rejects an empty or oversized JSON body")
	}
	var root map[string]any
	if err := json.Unmarshal(body, &root); err != nil || root == nil {
		if err == nil {
			err = fmt.Errorf("JSON root is not an object")
		}
		return nil, fmt.Errorf("strict Codex privacy policy cannot parse request metadata: %w", err)
	}

	// Establish the canonical request cache identity before walking nested
	// metadata. A nested caller-supplied key must never win merely because the
	// metadata container happens to be visited first. The deterministic scan
	// also handles cache keys that exist only in an embedded metadata carrier.
	primeCodexPrivacyPromptCacheCanonical(root, account, ids, secret)

	// Normalize root aliases to one exact key. Keeping multiple spellings would
	// create another client-controlled carrier even when every value is mapped.
	aliasKeys := make([]string, 0)
	for key := range root {
		if key != "prompt_cache_key" && normalizeCodexPrivacyKey(key) == "prompt_cache_key" {
			aliasKeys = append(aliasKeys, key)
		}
	}
	sort.Strings(aliasKeys)
	for _, key := range aliasKeys {
		if _, exists := root["prompt_cache_key"]; !exists {
			if raw, ok := root[key].(string); ok {
				root["prompt_cache_key"] = codexPrivacyPromptCacheKey(account, ids, secret, raw)
			}
		}
		delete(root, key)
	}

	if raw, ok := root["prompt_cache_key"].(string); ok {
		root["prompt_cache_key"] = codexPrivacyPromptCacheKey(account, ids, secret, raw)
	} else if _, exists := root["prompt_cache_key"]; exists {
		delete(root, "prompt_cache_key")
	}

	// Ensure the body has one canonical metadata container, even when the
	// client omitted it. This keeps header/body identity snapshots aligned.
	clientMetadata, ok := root["client_metadata"].(map[string]any)
	if !ok || clientMetadata == nil {
		clientMetadata = make(map[string]any)
		root["client_metadata"] = clientMetadata
	}
	sanitizeCodexPrivacyMetadataMap(clientMetadata, ids, account, secret, 0)

	for key, value := range root {
		normalized := normalizeCodexPrivacyKey(key)
		switch {
		case normalized == "client_metadata":
			// Only the canonical key is accepted. JSON keys are case-sensitive,
			// so aliases such as Client-Metadata/client.metadata would otherwise
			// survive beside the sanitized container as an uninspected channel.
			if key != "client_metadata" {
				delete(root, key)
			}
		case isCodexPrivacyIdentityKey(key):
			root[key] = ids.installationID
		case isCodexPrivacySessionKey(key):
			if ids.sessionID == "" {
				delete(root, key)
			} else {
				root[key] = ids.sessionID
			}
		case isCodexPrivacyThreadKey(key):
			if ids.threadID == "" {
				delete(root, key)
			} else {
				root[key] = ids.threadID
			}
		case isCodexPrivacyTurnKey(key):
			if ids.turnID == "" {
				delete(root, key)
			} else {
				root[key] = ids.turnID
			}
		case isCodexPrivacyWindowKey(key):
			if ids.windowID == "" {
				delete(root, key)
			} else {
				root[key] = ids.windowID
			}
		case normalized == "prompt_cache_key":
			raw, ok := value.(string)
			if !ok {
				delete(root, key)
			} else {
				root[key] = codexPrivacyPromptCacheKey(account, ids, secret, raw)
			}
		case normalized == "conversation_id":
			raw, ok := value.(string)
			if !ok || strings.TrimSpace(raw) == "" || ids.sessionID == "" {
				delete(root, key)
			} else {
				mapped := ids.promptCacheCanonical
				if mapped == "" {
					mapped = codexPrivacyConversationID(account, ids, secret, raw)
				}
				root["conversation_id"] = mapped
				if key != "conversation_id" {
					delete(root, key)
				}
			}
		case normalized == "conversation":
			// The top-level conversation object is a client-controlled
			// continuation carrier. Its schema is not needed on the stateless
			// HTTP privacy path, so reject it rather than preserving nested IDs.
			delete(root, key)
		case normalized == "previous_response_id":
			// HTTP privacy requests are stateless (store=false); forwarding a
			// client response chain would reintroduce an opaque account/session
			// association and is inconsistent with the normal Forward path.
			delete(root, key)
		case normalized == "metadata":
			// Generic metadata is an optional client-controlled carrier. Treat
			// it with the same strict nested policy instead of assuming that
			// only the Codex-named containers can contain local identifiers.
			if nested, ok := value.(map[string]any); ok {
				sanitizeCodexPrivacyMetadataMap(nested, ids, account, secret, 0)
			} else {
				delete(root, key)
			}
		case normalized == "x_codex_turn_metadata" || normalized == "responsesapi_client_metadata":
			if (normalized == "responsesapi_client_metadata" && key != normalized) ||
				(normalized == "x_codex_turn_metadata" && key != "x-codex-turn-metadata") {
				// Alias carriers are not protocol-required.  Drop them after
				// inspecting no content so a spelling variant cannot become a
				// second outbound association channel.
				delete(root, key)
				continue
			}
			if nested, ok := value.(map[string]any); ok {
				sanitizeCodexPrivacyMetadataMap(nested, ids, account, secret, 0)
			} else if raw, ok := value.(string); ok {
				var nested map[string]any
				if json.Unmarshal([]byte(raw), &nested) != nil || nested == nil {
					delete(root, key)
				} else {
					sanitizeCodexPrivacyMetadataMap(nested, ids, account, secret, 0)
					if rebuilt, err := json.Marshal(nested); err == nil {
						root[key] = string(rebuilt)
					} else {
						delete(root, key)
					}
				}
			} else {
				delete(root, key)
			}
		case isCodexPrivacyLineageKey(key):
			delete(root, key)
		case normalized == "thread_source" || normalized == "subagent_kind" || normalized == "agent_name":
			root[key] = "gateway"
		case isCodexPrivacySensitiveMetadataKey(key):
			delete(root, key)
		}
	}

	result, err := json.Marshal(root)
	if err != nil {
		return nil, fmt.Errorf("serialize strict Codex privacy body: %w", err)
	}
	return result, nil
}

// sanitizeCodexPrivacyHeaders is the final outbound header invariant. It runs
// after account overrides, beta-feature injection and routing hints so a later
// transform cannot reintroduce client-local identifiers.
func sanitizeCodexPrivacyHeaders(h http.Header, account *Account, ids *codexFingerprintIDs, body []byte, secret string) {
	if h == nil || !codexPrivacyEnabled(account) {
		return
	}
	if ids == nil || strings.TrimSpace(secret) == "" {
		// A missing snapshot is a policy failure. The request builder normally
		// returns an error before reaching this point; defensively remove all
		// client identity carriers so a future caller cannot fall through raw.
		for _, key := range []string{
			"cookie", "traceparent", "tracestate", "x-codex-turn-state",
			"x-codex-installation-id", "x-codex-window-id", "x-codex-turn-metadata",
			"session-id", "session_id", "conversation_id", "thread-id", "thread_id",
			"x-client-request-id", "x-codex-parent-thread-id", "x-codex-root-thread-id",
			"x-codex-forked-from-thread-id", "x-oai-attestation",
		} {
			h.Del(key)
		}
		return
	}
	for _, key := range []string{
		"cookie", "traceparent", "tracestate", "x-codex-turn-state",
		"x-codex-ws-stream-request-start-ms", "x-forwarded-for", "x-forwarded-host",
		"x-forwarded-proto", "x-real-ip", "referer", "origin", "x-oai-attestation",
		"x-codex-parent-thread-id", "x-codex-root-thread-id", "x-codex-forked-from-thread-id",
		// Responses-lite is an internal execution hint copied by both HTTP
		// builders. There is no reviewed server-side derivation for the normal
		// Responses path, so a client value would be an opaque correlation tag.
		responsesLiteHeaderKey,
		// Client-selected timeout values are both an observable fingerprint and
		// a source of request-behavior drift. The gateway owns these values for
		// privacy accounts; transport-level timeouts are configured server-side.
		"x-stainless-timeout", "x-stainless-read-timeout", "x-stainless-connect-timeout",
		"x-request-timeout", "request-timeout", "grpc-timeout",
	} {
		// Inbound Authorization is never copied by the request builders; the
		// selected account's freshly built bearer remains in the header.
		h.Del(key)
	}
	// These headers are protocol choices, not user metadata. Rebuild them from
	// the normalized request rather than preserving arbitrary client values.
	h.Set("content-type", "application/json")
	stream := gjson.GetBytes(body, "stream")
	if stream.Exists() && stream.Bool() {
		h.Set("accept", "text/event-stream")
	} else {
		h.Set("accept", "application/json")
	}
	// OAuth Responses does not require a client-supplied OpenAI-Beta token in
	// the v177 HTTP path. Drop all inbound/compat values here; any future
	// server-generated beta feature must be added by a dedicated, reviewed
	// transform before this finalizer.
	h.Del("openai-beta")
	for key := range h {
		lower := strings.ToLower(strings.TrimSpace(key))
		if strings.HasPrefix(lower, "x-codex-") {
			switch lower {
			case "x-codex-installation-id", "x-codex-window-id", "x-codex-turn-metadata", "x-codex-beta-features", "x-codex-routing-hint":
				// allowed and rewritten below
			default:
				h.Del(key)
			}
		}
	}
	// The privacy HTTP path exposes one gateway-owned capability tuple. Even a
	// finite client feature set can become a persistent bit-vector, and the WS
	// feature is irrelevant on this transport. remote_compaction_v2 is already
	// the v177 canonical OAuth default injected by applyOpenAICodexBetaFeatures.
	h.Set("x-codex-beta-features", openAIRemoteCompactionV2Feature)
	applyCodexFingerprintHeaders(h, ids)
	if ids.mode == codexFingerprintDevice {
		// Device-only convergence is still a privacy-enabled mode. Optional
		// session carriers have no safe replacement in this mode, so remove
		// them rather than leaking the original client values.
		for _, key := range []string{
			"session-id", "session_id", "conversation_id", "thread-id", "thread_id",
			"x-client-request-id", "x-codex-window-id",
		} {
			h.Del(key)
		}
	}
	// A later compatibility path may have overwritten x-client-request-id;
	// pin it to the same gateway thread snapshot as the other carriers.
	if ids.mode != codexFingerprintDevice {
		h.Set("x-client-request-id", ids.threadID)
	}
	// The legacy global identity-enforcement switch is intentionally not an
	// opt-out for privacy-enabled OAuth accounts. It can disable the earlier
	// builder-level identity pairing and would otherwise let an account/custom
	// browser User-Agent survive the final header transforms. Compatibility
	// bridges may deliberately omit originator, but the client-controlled UA and
	// version must still be replaced at the final boundary.
	if account != nil && account.Type == AccountTypeOAuth {
		identity := resolveCodexOutboundIdentity("")
		h.Set("user-agent", identity.userAgent)
		h.Set("version", identity.version)
		if h.Get("originator") != "" {
			h.Set("originator", identity.originator)
		} else {
			h.Del("originator")
		}
	}
	h.Set("accept-language", "en-US,en;q=0.9")
	if raw := strings.TrimSpace(h.Get("x-codex-turn-metadata")); raw != "" {
		var metadata map[string]any
		if json.Unmarshal([]byte(raw), &metadata) != nil || metadata == nil {
			h.Del("x-codex-turn-metadata")
		} else {
			sanitizeCodexPrivacyMetadataMap(metadata, ids, account, secret, 0)
			if rebuilt, err := json.Marshal(metadata); err == nil {
				h.Set("x-codex-turn-metadata", string(rebuilt))
			} else {
				h.Del("x-codex-turn-metadata")
			}
		}
	}
	if ids.sessionID != "" {
		if rawConversation := strings.TrimSpace(h.Get("conversation_id")); rawConversation != "" {
			mappedConversation := ids.sessionID
			rawCache := strings.TrimSpace(gjson.GetBytes(body, "prompt_cache_key").String())
			if rawCache == "" {
				var bodyRoot map[string]any
				if json.Unmarshal(body, &bodyRoot) == nil {
					rawCache = strings.TrimSpace(findCodexPrivacyPromptCacheKey(bodyRoot, 0))
				}
			}
			if ids.promptCacheCanonical != "" {
				mappedConversation = ids.promptCacheCanonical
			} else if rawCache != "" {
				mappedConversation = codexPrivacyPromptCacheKey(account, ids, secret, rawCache)
			} else if rawConversation != ids.sessionID && rawConversation != ids.clientSessionID {
				mappedConversation = codexPrivacyConversationID(account, ids, secret, rawConversation)
			}
			h.Set("session_id", ids.sessionID)
			h.Set("session-id", ids.sessionID)
			h.Set("conversation_id", mappedConversation)
		}
	}
	// Authorization is intentionally preserved here: it was built from the
	// selected account immediately before this finalizer, while inbound client
	// Authorization/Cookie values were never copied into the request.
}
