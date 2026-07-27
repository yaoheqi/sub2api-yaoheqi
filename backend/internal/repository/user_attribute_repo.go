package repository

import (
	"context"
	"fmt"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/ent/userattributedefinition"
	"github.com/Wei-Shaw/sub2api/ent/userattributevalue"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/lib/pq"
)

// UserAttributeDefinitionRepository implementation
type userAttributeDefinitionRepository struct {
	client *dbent.Client
}

// NewUserAttributeDefinitionRepository creates a new repository instance
func NewUserAttributeDefinitionRepository(client *dbent.Client) service.UserAttributeDefinitionRepository {
	return &userAttributeDefinitionRepository{client: client}
}

func (r *userAttributeDefinitionRepository) Create(ctx context.Context, def *service.UserAttributeDefinition) error {
	client := clientFromContext(ctx, r.client)

	created, err := client.UserAttributeDefinition.Create().
		SetKey(def.Key).
		SetName(def.Name).
		SetDescription(def.Description).
		SetType(string(def.Type)).
		SetOptions(toEntOptions(def.Options)).
		SetRequired(def.Required).
		SetValidation(toEntValidation(def.Validation)).
		SetPlaceholder(def.Placeholder).
		SetEnabled(def.Enabled).
		Save(ctx)

	if err != nil {
		return translatePersistenceError(err, nil, service.ErrAttributeKeyExists)
	}

	def.ID = created.ID
	def.DisplayOrder = created.DisplayOrder
	def.CreatedAt = created.CreatedAt
	def.UpdatedAt = created.UpdatedAt
	return nil
}

func (r *userAttributeDefinitionRepository) GetByID(ctx context.Context, id int64) (*service.UserAttributeDefinition, error) {
	client := clientFromContext(ctx, r.client)

	e, err := client.UserAttributeDefinition.Query().
		Where(userattributedefinition.IDEQ(id)).
		Only(ctx)
	if err != nil {
		return nil, translatePersistenceError(err, service.ErrAttributeDefinitionNotFound, nil)
	}
	return defEntityToService(e), nil
}

func (r *userAttributeDefinitionRepository) GetByKey(ctx context.Context, key string) (*service.UserAttributeDefinition, error) {
	client := clientFromContext(ctx, r.client)

	e, err := client.UserAttributeDefinition.Query().
		Where(userattributedefinition.KeyEQ(key)).
		Only(ctx)
	if err != nil {
		return nil, translatePersistenceError(err, service.ErrAttributeDefinitionNotFound, nil)
	}
	return defEntityToService(e), nil
}

func (r *userAttributeDefinitionRepository) Update(ctx context.Context, def *service.UserAttributeDefinition) error {
	client := clientFromContext(ctx, r.client)

	updated, err := client.UserAttributeDefinition.UpdateOneID(def.ID).
		SetName(def.Name).
		SetDescription(def.Description).
		SetType(string(def.Type)).
		SetOptions(toEntOptions(def.Options)).
		SetRequired(def.Required).
		SetValidation(toEntValidation(def.Validation)).
		SetPlaceholder(def.Placeholder).
		SetDisplayOrder(def.DisplayOrder).
		SetEnabled(def.Enabled).
		Save(ctx)

	if err != nil {
		return translatePersistenceError(err, service.ErrAttributeDefinitionNotFound, service.ErrAttributeKeyExists)
	}

	def.UpdatedAt = updated.UpdatedAt
	return nil
}

func (r *userAttributeDefinitionRepository) Delete(ctx context.Context, id int64) error {
	client := clientFromContext(ctx, r.client)

	_, err := client.UserAttributeDefinition.Delete().
		Where(userattributedefinition.IDEQ(id)).
		Exec(ctx)
	return translatePersistenceError(err, service.ErrAttributeDefinitionNotFound, nil)
}

func (r *userAttributeDefinitionRepository) List(ctx context.Context, enabledOnly bool) ([]service.UserAttributeDefinition, error) {
	client := clientFromContext(ctx, r.client)

	q := client.UserAttributeDefinition.Query()
	if enabledOnly {
		q = q.Where(userattributedefinition.EnabledEQ(true))
	}

	entities, err := q.Order(dbent.Asc(userattributedefinition.FieldDisplayOrder)).All(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]service.UserAttributeDefinition, 0, len(entities))
	for _, e := range entities {
		result = append(result, *defEntityToService(e))
	}
	return result, nil
}

func (r *userAttributeDefinitionRepository) UpdateDisplayOrders(ctx context.Context, orders map[int64]int) error {
	if len(orders) == 0 {
		return nil
	}
	ids := make([]int64, 0, len(orders))
	values := make([]int64, 0, len(orders))
	for id, order := range orders {
		ids = append(ids, id)
		values = append(values, int64(order))
	}
	result, err := clientFromContext(ctx, r.client).ExecContext(ctx, `
		UPDATE user_attribute_definitions AS definitions
		SET display_order = data.display_order::integer,
			updated_at = NOW()
		FROM unnest($1::bigint[], $2::bigint[]) AS data(id, display_order)
		WHERE definitions.id = data.id
	`, pq.Array(ids), pq.Array(values))
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != int64(len(ids)) {
		return service.ErrAttributeDefinitionNotFound
	}
	return nil
}

func (r *userAttributeDefinitionRepository) ExistsByKey(ctx context.Context, key string) (bool, error) {
	client := clientFromContext(ctx, r.client)
	return client.UserAttributeDefinition.Query().
		Where(userattributedefinition.KeyEQ(key)).
		Exist(ctx)
}

// UserAttributeValueRepository implementation
type userAttributeValueRepository struct {
	client *dbent.Client
}

// NewUserAttributeValueRepository creates a new repository instance
func NewUserAttributeValueRepository(client *dbent.Client) service.UserAttributeValueRepository {
	return &userAttributeValueRepository{client: client}
}

func (r *userAttributeValueRepository) GetByUserID(ctx context.Context, userID int64) ([]service.UserAttributeValue, error) {
	client := clientFromContext(ctx, r.client)

	entities, err := client.UserAttributeValue.Query().
		Where(userattributevalue.UserIDEQ(userID)).
		All(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]service.UserAttributeValue, 0, len(entities))
	for _, e := range entities {
		result = append(result, service.UserAttributeValue{
			ID:          e.ID,
			UserID:      e.UserID,
			AttributeID: e.AttributeID,
			Value:       e.Value,
			CreatedAt:   e.CreatedAt,
			UpdatedAt:   e.UpdatedAt,
		})
	}
	return result, nil
}

func (r *userAttributeValueRepository) GetByUserIDs(ctx context.Context, userIDs []int64) ([]service.UserAttributeValue, error) {
	if len(userIDs) == 0 {
		return []service.UserAttributeValue{}, nil
	}

	client := clientFromContext(ctx, r.client)

	entities, err := client.UserAttributeValue.Query().
		Where(userattributevalue.UserIDIn(userIDs...)).
		All(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]service.UserAttributeValue, 0, len(entities))
	for _, e := range entities {
		result = append(result, service.UserAttributeValue{
			ID:          e.ID,
			UserID:      e.UserID,
			AttributeID: e.AttributeID,
			Value:       e.Value,
			CreatedAt:   e.CreatedAt,
			UpdatedAt:   e.UpdatedAt,
		})
	}
	return result, nil
}

func (r *userAttributeValueRepository) UpsertBatch(ctx context.Context, userID int64, inputs []service.UpdateUserAttributeInput) error {
	if len(inputs) == 0 {
		return nil
	}

	latest := make(map[int64]string, len(inputs))
	for _, input := range inputs {
		latest[input.AttributeID] = input.Value
	}
	attributeIDs := make([]int64, 0, len(latest))
	values := make([]string, 0, len(latest))
	for attributeID, value := range latest {
		attributeIDs = append(attributeIDs, attributeID)
		values = append(values, value)
	}
	_, err := clientFromContext(ctx, r.client).ExecContext(ctx, `
		INSERT INTO user_attribute_values (user_id, attribute_id, value, created_at, updated_at)
		SELECT $1, data.attribute_id, data.value, NOW(), NOW()
		FROM unnest($2::bigint[], $3::text[]) AS data(attribute_id, value)
		ON CONFLICT (user_id, attribute_id)
		DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at
	`, userID, pq.Array(attributeIDs), pq.Array(values))
	if err != nil {
		return fmt.Errorf("batch upsert user attributes: %w", err)
	}
	return nil
}

func (r *userAttributeValueRepository) DeleteByAttributeID(ctx context.Context, attributeID int64) error {
	client := clientFromContext(ctx, r.client)

	_, err := client.UserAttributeValue.Delete().
		Where(userattributevalue.AttributeIDEQ(attributeID)).
		Exec(ctx)
	return err
}

func (r *userAttributeValueRepository) DeleteByUserID(ctx context.Context, userID int64) error {
	client := clientFromContext(ctx, r.client)

	_, err := client.UserAttributeValue.Delete().
		Where(userattributevalue.UserIDEQ(userID)).
		Exec(ctx)
	return err
}

// Helper functions for entity to service conversion
func defEntityToService(e *dbent.UserAttributeDefinition) *service.UserAttributeDefinition {
	if e == nil {
		return nil
	}
	return &service.UserAttributeDefinition{
		ID:           e.ID,
		Key:          e.Key,
		Name:         e.Name,
		Description:  e.Description,
		Type:         service.UserAttributeType(e.Type),
		Options:      toServiceOptions(e.Options),
		Required:     e.Required,
		Validation:   toServiceValidation(e.Validation),
		Placeholder:  e.Placeholder,
		DisplayOrder: e.DisplayOrder,
		Enabled:      e.Enabled,
		CreatedAt:    e.CreatedAt,
		UpdatedAt:    e.UpdatedAt,
	}
}

// Type conversion helpers (map types <-> service types)
func toEntOptions(opts []service.UserAttributeOption) []map[string]any {
	if opts == nil {
		return []map[string]any{}
	}
	result := make([]map[string]any, len(opts))
	for i, o := range opts {
		result[i] = map[string]any{"value": o.Value, "label": o.Label}
	}
	return result
}

func toServiceOptions(opts []map[string]any) []service.UserAttributeOption {
	if opts == nil {
		return []service.UserAttributeOption{}
	}
	result := make([]service.UserAttributeOption, len(opts))
	for i, o := range opts {
		result[i] = service.UserAttributeOption{
			Value: getString(o, "value"),
			Label: getString(o, "label"),
		}
	}
	return result
}

func toEntValidation(v service.UserAttributeValidation) map[string]any {
	result := map[string]any{}
	if v.MinLength != nil {
		result["min_length"] = *v.MinLength
	}
	if v.MaxLength != nil {
		result["max_length"] = *v.MaxLength
	}
	if v.Min != nil {
		result["min"] = *v.Min
	}
	if v.Max != nil {
		result["max"] = *v.Max
	}
	if v.Pattern != nil {
		result["pattern"] = *v.Pattern
	}
	if v.Message != nil {
		result["message"] = *v.Message
	}
	return result
}

func toServiceValidation(v map[string]any) service.UserAttributeValidation {
	result := service.UserAttributeValidation{}
	if val := getInt(v, "min_length"); val != nil {
		result.MinLength = val
	}
	if val := getInt(v, "max_length"); val != nil {
		result.MaxLength = val
	}
	if val := getInt(v, "min"); val != nil {
		result.Min = val
	}
	if val := getInt(v, "max"); val != nil {
		result.Max = val
	}
	if val := getStringPtr(v, "pattern"); val != nil {
		result.Pattern = val
	}
	if val := getStringPtr(v, "message"); val != nil {
		result.Message = val
	}
	return result
}

// Helper functions for type conversion
func getString(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getStringPtr(m map[string]any, key string) *string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return &s
		}
	}
	return nil
}

func getInt(m map[string]any, key string) *int {
	if v, ok := m[key]; ok {
		switch n := v.(type) {
		case int:
			return &n
		case int64:
			i := int(n)
			return &i
		case float64:
			i := int(n)
			return &i
		}
	}
	return nil
}
