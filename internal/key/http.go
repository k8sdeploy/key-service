package key

import (
	"encoding/json"
	"net/http"
	"time"

	bugLog "github.com/bugfixes/go-bugfixes/logs"
	"github.com/go-chi/chi/v5"
)

type ResponseItem struct {
	Status string `json:"status"`

	User        string `json:"user_service,omitempty"`
	Hooks       string `json:"hooks_service,omitempty"`
	Company     string `json:"company_service,omitempty"`
	Billing     string `json:"billing_service,omitempty"`
	Permissions string `json:"permissions,omitempty"`
}

func jsonResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (k Key) CreateHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		jsonResponse(w, http.StatusBadRequest, &ResponseItem{
			Status: "missing user-id",
		})
		return
	}

	if vaultKey := r.Header.Get("X-Service-Key"); vaultKey == "" {
		jsonResponse(w, http.StatusBadRequest, &ResponseItem{
			Status: "missing vault-key",
		})
		return
	} else if !k.ValidateServiceKey(vaultKey) {
		jsonResponse(w, http.StatusBadRequest, &ResponseItem{
			Status: "invalid service key",
		})
		return
	}

	keys, err := k.GetKeys(25)
	if err != nil {
		bugLog.Info(err)
		jsonResponse(w, http.StatusInternalServerError, &ResponseItem{
			Status: "internal error",
		})
		return
	}

	if err := NewMongo(k.Config).Create(DataSet{
		UserID:    userID,
		Generated: time.Now().Unix(),
		Keys: struct {
			UserService        string `json:"user_service" bson:"user_service"`
			HooksService       string `json:"hooks_service" bson:"hooks_service"`
			CompanyService     string `json:"company_service" bson:"company_service"`
			BillingService     string `json:"billing_service" bson:"billing_service"`
			PermissionsService string `json:"permissions_service" bson:"permissions_service"`
		}{
			UserService:        keys.User,
			HooksService:       keys.Hooks,
			CompanyService:     keys.Company,
			BillingService:     keys.Billing,
			PermissionsService: keys.Permissions,
		},
	}); err != nil {
		bugLog.Info(err)
		jsonResponse(w, http.StatusInternalServerError, &ResponseItem{
			Status: "internal error",
		})
		return
	}

	jsonResponse(w, http.StatusOK, keys)
}

func (k Key) GetHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("x-user-id")
	if userID == "" {
		jsonResponse(w, http.StatusBadRequest, &ResponseItem{
			Status: "missing user-id",
		})
		return
	}

	if vaultKey := r.Header.Get("X-Service-Key"); vaultKey == "" {
		jsonResponse(w, http.StatusBadRequest, &ResponseItem{
			Status: "missing vault-key",
		})
		return
	} else if !k.ValidateServiceKey(vaultKey) {
		jsonResponse(w, http.StatusBadRequest, &ResponseItem{
			Status: "invalid service key",
		})
		return
	}

	keys, err := NewMongo(k.Config).Get(userID)
	if err != nil {
		bugLog.Info(err)
		jsonResponse(w, http.StatusInternalServerError, &ResponseItem{
			Status: "internal error",
		})
		return
	}

	if keys == nil {
		jsonResponse(w, http.StatusNotFound, &ResponseItem{
			Status: "not found",
		})
		return
	}

	jsonResponse(w, http.StatusOK, &ResponseItem{
		Status:      "ok",
		User:        keys.Keys.UserService,
		Hooks:       keys.Keys.HooksService,
		Company:     keys.Keys.CompanyService,
		Billing:     keys.Keys.BillingService,
		Permissions: keys.Keys.PermissionsService,
	})
}

// nolint: gocyclo
func (k Key) ValidateHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("x-user-id")
	if userID == "" {
		jsonResponse(w, http.StatusBadRequest, &ResponseItem{
			Status: "missing user-id",
		})
		return
	}

	checkKey := chi.URLParam(r, "key")
	if checkKey == "" {
		jsonResponse(w, http.StatusBadRequest, &ResponseItem{
			Status: "missing key",
		})
		return
	}

	keys, err := NewMongo(k.Config).Get(userID)
	if err != nil {
		bugLog.Info(err)
		jsonResponse(w, http.StatusInternalServerError, &ResponseItem{
			Status: "internal error",
		})
		return
	}

	if keys == nil {
		jsonResponse(w, http.StatusUnauthorized, &ResponseItem{
			Status: "not allowed",
		})
		return
	}

	userKey := keys.Keys.UserService
	hooksKey := keys.Keys.HooksService
	companyKey := keys.Keys.CompanyService
	billingKey := keys.Keys.BillingService
	permissionsKey := keys.Keys.PermissionsService

	if checkKey == userKey ||
		checkKey == hooksKey ||
		checkKey == companyKey ||
		checkKey == billingKey ||
		checkKey == permissionsKey {
		jsonResponse(w, http.StatusOK, &ResponseItem{
			Status: "ok",
		})
		return
	}

	jsonResponse(w, http.StatusUnauthorized, &ResponseItem{
		Status: "not allowed",
	})
}
