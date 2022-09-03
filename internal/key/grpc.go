package key

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/helper/pointerutil"
	"github.com/k8sdeploy/key-service/internal/config"
	pb "github.com/k8sdeploy/protos/generated/key/v1"
)

type Server struct {
	pb.UnimplementedKeyServiceServer
	Config *config.Config
}

// Missing
const (
	MissingUserID    = "missing user id"
	MissingCompanyID = "missing company id"
	//	MissingAgentKey   = "missing agent key"
	MissingServiceKey = "missing service key"
)

// Status
const (
	InvalidServiceKey = "invalid service key"
	//	InvalidAgentKey   = "invalid agent key"
	//	InvalidHookKey    = "invalid hook key"
	//	InvalidUserKey    = "invalid user key"
	SystemError = "system error"
)

// Agent
func (s *Server) CreateAgentKeys(c context.Context, r *pb.AgentRequest) (*pb.KeyResponse, error) {
	if r.ServiceKey != "" {
		if valid, _ := s.ValidateServiceKey(r.ServiceKey); !valid {
			return &pb.KeyResponse{
				Status: pointerutil.StringPtr(InvalidServiceKey),
			}, nil
		}
	} else {
		return &pb.KeyResponse{
			Status: pointerutil.StringPtr(MissingServiceKey),
		}, nil
	}

	return nil, nil
}

func (s *Server) GetAgentKeys(c context.Context, r *pb.AgentRequest) (*pb.KeyResponse, error) {
	if r.ServiceKey != "" {
		if valid, _ := s.ValidateServiceKey(r.ServiceKey); !valid {
			return &pb.KeyResponse{
				Status: pointerutil.StringPtr(InvalidServiceKey),
			}, nil
		}
	} else {
		return &pb.KeyResponse{
			Status: pointerutil.StringPtr(MissingServiceKey),
		}, nil
	}

	return nil, nil
}

func (s *Server) ValidateAgentKey(c context.Context, r *pb.ValidateSystemKeyRequest) (*pb.ValidKeyResponse, error) {
	if r.ServiceKey != "" {
		if valid, _ := s.ValidateServiceKey(r.ServiceKey); !valid {
			return &pb.ValidKeyResponse{
				Status: pointerutil.StringPtr(InvalidServiceKey),
			}, nil
		}
	} else {
		return &pb.ValidKeyResponse{
			Status: pointerutil.StringPtr(MissingServiceKey),
		}, nil
	}

	k := K8sKey{
		ID:     r.CompanyId,
		Key:    r.Key,
		Secret: r.Secret,
	}

	m := NewMongo(s.Config)
	valid, err := m.ValidateAgentKey(&k)
	if err != nil {
		return &pb.ValidKeyResponse{
			Status: pointerutil.StringPtr(SystemError),
		}, err
	}

	return &pb.ValidKeyResponse{
		Valid: valid,
	}, nil
}

// Hooks
func (s *Server) CreateHookKeys(c context.Context, r *pb.HooksRequest) (*pb.KeyResponse, error) {
	if r.ServiceKey != "" {
		if valid, _ := s.ValidateServiceKey(r.ServiceKey); !valid {
			return &pb.KeyResponse{
				Status: pointerutil.StringPtr(InvalidServiceKey),
			}, nil
		}
	} else {
		return &pb.KeyResponse{
			Status: pointerutil.StringPtr(MissingServiceKey),
		}, nil
	}

	if r.CompanyId == "" {
		return &pb.KeyResponse{
			Status: pointerutil.StringPtr(MissingCompanyID),
		}, nil
	}

	k := NewKey(s.Config)
	hk, err := k.GenerateKey(32)
	if err != nil {
		fmt.Printf("error generating hook key: %s\n", err)
		return &pb.KeyResponse{
			Status: pointerutil.StringPtr(SystemError),
		}, err
	}
	hs, err := k.GenerateKey(32)
	if err != nil {
		fmt.Printf("error generating hook secret: %s\n", err)
		return &pb.KeyResponse{
			Status: pointerutil.StringPtr(SystemError),
		}, err
	}
	d := K8sKey{
		ID:     r.CompanyId,
		Key:    hk,
		Secret: hs,
	}

	m := NewMongo(s.Config)
	if err := m.InsertHooksKey(d); err != nil {
		fmt.Printf("error inserting hook key: %s\n", err)
		return &pb.KeyResponse{
			Status: pointerutil.StringPtr(SystemError),
		}, err
	}

	return &pb.KeyResponse{
		Key:    hk,
		Secret: hs,
	}, nil
}

func (s *Server) GetHookKeys(c context.Context, r *pb.HooksRequest) (*pb.KeyResponse, error) {
	if r.ServiceKey != "" {
		if valid, _ := s.ValidateServiceKey(r.ServiceKey); !valid {
			return &pb.KeyResponse{
				Status: pointerutil.StringPtr(InvalidServiceKey),
			}, nil
		}
	} else {
		return &pb.KeyResponse{
			Status: pointerutil.StringPtr(MissingServiceKey),
		}, nil
	}

	return nil, nil
}

func (s *Server) GetHookKeysForCompany(c context.Context, r *pb.HooksRequest) (*pb.MultipleHooksResponse, error) {
	if r.ServiceKey != "" {
		if valid, _ := s.ValidateServiceKey(r.ServiceKey); !valid {
			return &pb.MultipleHooksResponse{
				Status: pointerutil.StringPtr(InvalidServiceKey),
			}, nil
		}
	} else {
		return &pb.MultipleHooksResponse{
			Status: pointerutil.StringPtr(MissingServiceKey),
		}, nil
	}

	return nil, nil
}

func (s *Server) ValidateHookKey(c context.Context, r *pb.ValidateSystemKeyRequest) (*pb.ValidKeyResponse, error) {
	if r.ServiceKey != "" {
		if valid, _ := s.ValidateServiceKey(r.ServiceKey); !valid {
			return &pb.ValidKeyResponse{
				Valid:  false,
				Status: pointerutil.StringPtr(InvalidServiceKey),
			}, nil
		}
	} else {
		return &pb.ValidKeyResponse{
			Valid:  false,
			Status: pointerutil.StringPtr(MissingServiceKey),
		}, nil
	}

	if r.CompanyId == "" {
		return &pb.ValidKeyResponse{
			Valid:  false,
			Status: pointerutil.StringPtr(MissingCompanyID),
		}, nil
	}
	valid, err := NewMongo(s.Config).ValidateHooksKey(K8sKey{
		ID:     r.CompanyId,
		Key:    r.Key,
		Secret: r.Secret,
	})
	if err != nil {
		fmt.Printf("validate key error: %v\n", err)
		return &pb.ValidKeyResponse{
			Valid:  false,
			Status: pointerutil.StringPtr(SystemError),
		}, err
	}

	fmt.Printf("validate key: %v\n", valid)
	return &pb.ValidKeyResponse{
		Valid: valid,
	}, nil
}

// User
func (s *Server) CreateUserKeys(c context.Context, r *pb.UserRequest) (*pb.KeyResponse, error) {
	if r.ServiceKey != "" {
		if valid, _ := s.ValidateServiceKey(r.ServiceKey); !valid {
			return &pb.KeyResponse{
				Status: pointerutil.StringPtr(InvalidServiceKey),
			}, nil
		}
	} else {
		return &pb.KeyResponse{
			Status: pointerutil.StringPtr(MissingServiceKey),
		}, nil
	}

	if r.UserId == "" {
		return &pb.KeyResponse{
			Status: pointerutil.StringPtr(MissingUserID),
		}, nil
	}

	k := NewKey(s.Config)
	uk, err := k.GenerateKey(32)
	if err != nil {
		fmt.Printf("error generating user key: %s\n", err)
		return &pb.KeyResponse{
			Status: pointerutil.StringPtr(SystemError),
		}, err
	}
	us, err := k.GenerateKey(32)
	if err != nil {
		fmt.Printf("error generating user secret: %s\n", err)
		return &pb.KeyResponse{
			Status: pointerutil.StringPtr(SystemError),
		}, err
	}
	d := UserKey{
		ID:     r.UserId,
		Key:    uk,
		Secret: us,
	}

	m := NewMongo(s.Config)
	if err := m.UpsertUser(d); err != nil {
		fmt.Printf("error upserting user: %s\n", err)
		return &pb.KeyResponse{
			Status: pointerutil.StringPtr(SystemError),
		}, err
	}

	return &pb.KeyResponse{
		Key:    uk,
		Secret: us,
	}, nil
}

func (s *Server) ValidateUserKeys(c context.Context, r *pb.ValidateUserKeyRequest) (*pb.ValidKeyResponse, error) {
	if r.ServiceKey != "" {
		if valid, _ := s.ValidateServiceKey(r.ServiceKey); !valid {
			fmt.Printf("invalid service key: %s\n", r.ServiceKey)
			return &pb.ValidKeyResponse{
				Valid:  false,
				Status: pointerutil.StringPtr(InvalidServiceKey),
			}, nil
		}
	} else {
		return &pb.ValidKeyResponse{
			Valid:  false,
			Status: pointerutil.StringPtr(MissingServiceKey),
		}, nil
	}

	return &pb.ValidKeyResponse{
		Valid: false,
	}, nil
}

func (s *Server) ValidateServiceKey(key string) (bool, error) {
	fmt.Printf("validating service key: %s, hooksService: %+v, orchestratorService: %+v\n",
		key,
		s.Config.HooksService,
		s.Config.Orchestrator)

	if key == s.Config.HooksService.Key ||
		key == s.Config.Orchestrator.Key {
		return true, nil
	}

	return false, nil
}

// func (s *Server) CreateAgentKeys(c context.Context, r *pb.CreateRequest) (*pb.KeyResponse, error) {
//	if r.UserId == "" {
//		bugLog.Info(MissingUserID)
//		return &pb.KeyResponse{
//			Status: pointerutil.StringPtr(MissingUserID),
//		}, nil
//	}
//
//	if r.ServiceKey == "" {
//		bugLog.Info(MissingServiceKey)
//		return &pb.KeyResponse{
//			Status: pointerutil.StringPtr(MissingServiceKey),
//		}, nil
//	}
//
//	k := NewKey(s.Config)
//	if !k.ValidateServiceKey(r.ServiceKey) {
//		bugLog.Info(InvalidServiceKey)
//		return &pb.KeyResponse{
//			Status: pointerutil.StringPtr(InvalidServiceKey),
//		}, nil
//	}
//
//	keys, err := k.GetKeys(25)
//	if err != nil {
//		bugLog.Info(err)
//		status := "internal error, 1"
//		return &pb.KeyResponse{
//			Status: pointerutil.StringPtr(status),
//		}, nil
//	}
//
//	if err := NewMongo(k.Config).Create(DataSet{
//		UserID:    r.UserId,
//		Generated: time.Now().Unix(),
//		Keys: struct {
//			UserService        string `json:"user_service" bson:"user_service"`
//			HooksService       string `json:"hooks_service" bson:"hooks_service"`
//			CompanyService     string `json:"company_service" bson:"company_service"`
//			BillingService     string `json:"billing_service" bson:"billing_service"`
//			PermissionsService string `json:"permissions_service" bson:"permissions_service"`
//		}{
//			UserService:        keys.User,
//			HooksService:       keys.Hooks,
//			CompanyService:     keys.Company,
//			BillingService:     keys.Billing,
//			PermissionsService: keys.Permissions,
//		},
//	}); err != nil {
//		bugLog.Info(err)
//		status := "internal error, 2"
//		return &pb.KeyResponse{
//			Status: pointerutil.StringPtr(status),
//		}, nil
//	}
//
//	return &pb.KeyResponse{
//		User:    keys.User,
//		Hooks:   keys.Hooks,
//		Company: keys.Company,
//		Billing: keys.Billing,
//	}, nil
// }
//
// func (s *Server) Get(c context.Context, r *pb.GetRequest) (*pb.KeyResponse, error) {
//	if r.UserId == "" {
//		bugLog.Info(MissingUserID)
//		return &pb.KeyResponse{
//			Status: pointerutil.StringPtr(MissingUserID),
//		}, nil
//	}
//
//	if r.ServiceKey == "" {
//		bugLog.Info(MissingServiceKey)
//		return &pb.KeyResponse{
//			Status: pointerutil.StringPtr(MissingServiceKey),
//		}, nil
//	}
//
//	k := NewKey(s.Config)
//	if !k.ValidateServiceKey(r.ServiceKey) {
//		bugLog.Info(InvalidServiceKey)
//		return &pb.KeyResponse{
//			Status: pointerutil.StringPtr(InvalidServiceKey),
//		}, nil
//	}
//
//	keys, err := NewMongo(k.Config).Get(r.UserId)
//	if err != nil {
//		bugLog.Info(err)
//		status := "internal error, 3"
//		return &pb.KeyResponse{
//			Status: pointerutil.StringPtr(status),
//		}, nil
//	}
//
//	if keys == nil {
//		status := "user not found"
//		bugLog.Info("no keys or expired for user")
//		return &pb.KeyResponse{
//			Status: pointerutil.StringPtr(status),
//		}, nil
//	}
//
//	return &pb.KeyResponse{
//		User:        keys.Keys.UserService,
//		Hooks:       keys.Keys.HooksService,
//		Company:     keys.Keys.CompanyService,
//		Billing:     keys.Keys.BillingService,
//		Permissions: keys.Keys.PermissionsService,
//	}, nil
// }
//
////nolint:gocyclo
// func (s *Server) Validate(c context.Context, r *pb.ValidateRequest) (*pb.ValidResponse, error) {
//	if r.UserId == "" {
//		bugLog.Info(MissingUserID)
//		return &pb.ValidResponse{
//			Status: pointerutil.StringPtr(MissingUserID),
//		}, nil
//	}
//
//	if r.ServiceKey == "" {
//		bugLog.Info(MissingServiceKey)
//		return &pb.ValidResponse{
//			Status: pointerutil.StringPtr(MissingServiceKey),
//		}, nil
//	}
//
//	if r.CheckKey == "" {
//		status := "missing check-key"
//		bugLog.Info(status)
//		return &pb.ValidResponse{
//			Status: &status,
//		}, nil
//	}
//
//	k := NewKey(s.Config)
//	if !k.ValidateServiceKey(r.ServiceKey) {
//		bugLog.Info(InvalidServiceKey)
//		return &pb.ValidResponse{
//			Valid:  false,
//			Status: pointerutil.StringPtr(InvalidServiceKey),
//		}, nil
//	}
//
//	if s.Config.Local.Development {
//		return &pb.ValidResponse{
//			Valid: true,
//		}, nil
//	}
//
//	keys, err := NewMongo(k.Config).Get(r.UserId)
//	if err != nil {
//		status := "internal error, 4"
//		bugLog.Info(err)
//		return &pb.ValidResponse{
//			Valid:  false,
//			Status: &status,
//		}, nil
//	}
//
//	if r.CheckKey == keys.Keys.UserService ||
//		r.CheckKey == keys.Keys.HooksService ||
//		r.CheckKey == keys.Keys.CompanyService ||
//		r.CheckKey == keys.Keys.BillingService ||
//		r.CheckKey == keys.Keys.PermissionsService {
//		return &pb.ValidResponse{
//			Valid: true,
//		}, nil
//	}
//
//	return &pb.ValidResponse{
//		Valid: false,
//	}, nil
// }
