package service

import (
	"fmt"
	"net"
	"net/http"
	"time"

	bugLog "github.com/bugfixes/go-bugfixes/logs"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/k8sdeploy/key-service/internal/config"
	"github.com/k8sdeploy/key-service/internal/key"
	pb "github.com/k8sdeploy/protos/generated/key/v1"
	"github.com/keloran/go-healthcheck"
	"github.com/keloran/go-probe"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	kitlog "github.com/go-kit/log"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/kit"
)

type Service struct {
	Config *config.Config
}

func (s *Service) Start() error {
	errChan := make(chan error)
	go startGRPC(s.Config.GRPCPort, errChan, s.Config)

	if !s.Config.Development {
		go startHTTP(s.Config.HTTPPort, errChan)
	}

	return <-errChan
}

func startGRPC(port int, errChan chan error, config *config.Config) {
	kOpts := []kit.Option{
		kit.WithDecider(func(methodFullName string, err error) bool {
			if err != nil {
				bugLog.Local().Infof("%s: %+v", methodFullName, err)
				return false
			}
			return true
		}),
	}
	opts := []grpc.ServerOption{
		grpc_middleware.WithStreamServerChain(
			kit.StreamServerInterceptor(kitlog.NewNopLogger(), kOpts...),
		),
		grpc_middleware.WithUnaryServerChain(
			kit.UnaryServerInterceptor(kitlog.NewNopLogger(), kOpts...),
		),
	}

	p := fmt.Sprintf(":%d", port)
	bugLog.Local().Infof("Starting Key GRPC: %s", p)
	lis, err := net.Listen("tcp", p)
	if err != nil {
		errChan <- bugLog.Errorf("failed to listen: %v", err)
	}
	gs := grpc.NewServer(opts...)
	reflection.Register(gs)
	pb.RegisterKeyServiceServer(gs, &key.Server{
		Config: config,
	})
	if err := gs.Serve(lis); err != nil {
		errChan <- bugLog.Errorf("failed to start grpc: %v", err)
	}
}

func startHTTP(port int, errChan chan error) {
	p := fmt.Sprintf(":%d", port)
	bugLog.Local().Infof("Starting Key HTTP: %s", p)

	r := chi.NewRouter()
	r.Use(middleware.Heartbeat("/ping"))
	r.Use(middleware.RequestID)
	r.Get("/health", healthcheck.HTTP)
	r.Get("/probe", probe.HTTP)

	srv := &http.Server{
		Addr:         p,
		Handler:      r,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  10 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		errChan <- bugLog.Errorf("failed to start http: %v", err)
	}
}
