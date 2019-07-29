package main

import (
  "context"
  "crypto/sha256"
  "encoding/base64"
  "net"
  "strings"
  "gopkg.in/yaml.v2"
  "io/ioutil"
  "fmt"
  "os"
  log "github.com/sirupsen/logrus"

  "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
  auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
  envoy_type "github.com/envoyproxy/go-control-plane/envoy/type"
  "github.com/gogo/googleapis/google/rpc"
  "google.golang.org/grpc"
)


type Authorizations struct {
  Bearer []string
  Basic []string
  Headers map[string]struct{}
}

type AuthorizationServer struct{
  authorizations map[string]*Authorizations
}

func (server *AuthorizationServer) CheckHeader(hostname string, authHeader string) (string, bool) {
  if _, ok := server.authorizations[hostname]; !ok {
    if !server.Load(hostname) {
      return "", false // Failed to load config
    }
  }
  split := strings.Split(authHeader, " ")
  if len(split) != 2 {
    return "", false // No properly formed auth header
  }

  header := strings.ToLower(split[0]) + " " + split[1]
  if _, isPresent := server.authorizations[hostname].Headers[header]; !isPresent {
    log.WithFields(log.Fields{"domain": hostname}).Debug("reload authorizations")
    delete(server.authorizations, hostname);
    server.Load(hostname)
  }
  _, isPresent := server.authorizations[hostname].Headers[header]
  return split[1], isPresent
}

func (server *AuthorizationServer) Load(hostname string) bool {
  fn := fmt.Sprintf("/etc/switchboard/authorizations/%s.yaml", strings.ToLower(hostname))
  yamlFile, err := ioutil.ReadFile(fn)
  if err != nil {
    log.WithFields(log.Fields{
      "domain": hostname,
      "file": fn,
    }).Debug("no authorizations file exists")
    return false
  }

  auths := new(Authorizations)
  err = yaml.Unmarshal(yamlFile, &auths)
  if err != nil {
    log.WithFields(log.Fields{
      "domain": hostname,
      "file": fn,
      "error": err,
    }).Warn("could not unmarshal yaml file")
    return false
  }
  server.authorizations[hostname] = auths
  server.authorizations[hostname].Headers = make(map[string]struct{})
  for _, v := range server.authorizations[hostname].Basic {
    server.authorizations[hostname].Headers["basic " + v] = struct{}{}
  }
  for _, v := range server.authorizations[hostname].Bearer {
    server.authorizations[hostname].Headers["bearer " + v] = struct{}{}
  }
  log.WithFields(log.Fields{"domain": hostname, "file": fn}).Debug("loaded authorizations")
  return true
}

func (a *AuthorizationServer) GetRateLimitedSuccess(authId string) (*auth.CheckResponse, error) {
  sha := sha256.New()
  sha.Write([]byte(authId))
  authSha := base64.StdEncoding.EncodeToString(sha.Sum(nil))
  return &auth.CheckResponse{
    Status: &rpc.Status{
      Code: int32(rpc.OK),
    },
    HttpResponse: &auth.CheckResponse_OkResponse{
      OkResponse: &auth.OkHttpResponse{
        Headers: []*core.HeaderValueOption{
          {
            Header: &core.HeaderValue{
              Key:   "x-ext-auth-ratelimit",
              Value: authSha,
            },
          },
        },
      },
    },
  }, nil
}

func (a *AuthorizationServer) GetSuccess() (*auth.CheckResponse, error) {
  return &auth.CheckResponse{
    Status: &rpc.Status{
      Code: int32(rpc.OK),
    },
    HttpResponse: &auth.CheckResponse_OkResponse{
      OkResponse: &auth.OkHttpResponse{
        Headers: []*core.HeaderValueOption{},
      },
    },
  }, nil
}

func (a *AuthorizationServer) GetFailure(body string) (*auth.CheckResponse, error) {
  return &auth.CheckResponse{
    Status: &rpc.Status{
      Code: int32(rpc.UNAUTHENTICATED),
    },
    HttpResponse: &auth.CheckResponse_DeniedResponse{
      DeniedResponse: &auth.DeniedHttpResponse{
        Status: &envoy_type.HttpStatus{
          Code: envoy_type.StatusCode_Unauthorized,
        },
        Body: body,
      },
    },
  }, nil
}

// inject a header that can be used for future rate limiting
func (a *AuthorizationServer) Check(ctx context.Context, req *auth.CheckRequest) (*auth.CheckResponse, error) {
  hostname := req.Attributes.Request.Http.Headers[":authority"]
  authHeader, hasAuthHeader := req.Attributes.Request.Http.Headers["authorization"]
  authId, valid := a.CheckHeader(hostname, authHeader)
  log.WithFields(log.Fields{
    "domain": hostname,
    "id": authId,
    "valid": valid,
  }).Debug("checked authorization")
  if valid {
    return a.GetRateLimitedSuccess(authId)
  }
  if hasAuthHeader {
    return a.GetFailure("invalid authorization")
  }
  if _, hasSecurity := a.authorizations[hostname]; hasSecurity {
    return a.GetFailure("authorization required to access " + hostname)
  }
  return a.GetSuccess()
}

func main() {
  port := os.Args[1]
  if len(os.Args) > 2 {
    level := strings.ToLower(os.Args[2])
    if len(level) <= 0 || level == "info" {
      log.SetLevel(log.InfoLevel)
    } else if level == "debug" {
      log.SetLevel(log.DebugLevel)
    } else if level == "warn" {
      log.SetLevel(log.WarnLevel)
    } else if level == "trace" {
      log.SetLevel(log.TraceLevel)
    } else if level == "error" {
      log.SetLevel(log.ErrorLevel)
    } else if level == "fatal" {
      log.SetLevel(log.FatalLevel)
    } else {
      log.WithFields(log.Fields{"input_level": level}).Fatal("invalid log level")
    }
  }
  if len(os.Args) > 3 && os.Args[3] == "json" {
    log.SetFormatter(&log.JSONFormatter{})
  } else {
    log.SetFormatter(&log.TextFormatter{})
  }

  lis, err := net.Listen("tcp", ":" + port)
  if err != nil {
    log.WithFields(log.Fields{"error": err, "port": port}).Fatal("failed to listen")
  }

  grpcServer := grpc.NewServer()
  authServer := &AuthorizationServer{}
  authServer.authorizations = map[string]*Authorizations{}

  auth.RegisterAuthorizationServer(grpcServer, authServer)

  if err := grpcServer.Serve(lis); err != nil {
    log.WithFields(log.Fields{"error": err}).Fatal("failed to start server")
  }
}