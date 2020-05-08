# Switchboard
----

A simple-to-configure front proxy in a docker container, built on Envoy.

## Features

* GRPC (HTTP2.0) and WebSockets work side-by-side on the same paths with HTTP1.1
* TLS termination with automatic certificate generation via CertBot/LetsEncrypt
* Redirection (HTTP->HTTPS, domain1->domain2, etc.)
* Authorization (`Basic` and `Bearer` HTTP authentication)
* Observability integration (statsd)
* Stateless (certificate backup via S3)
* Sharding (different subdomains for different environments)

## Motivation

I have a Kubernetes deployment running in production which needs to route traffic from multiple different domains to different containers. I also run a development version of the same stack on my Linux computer at my house, and I want to use `kustomization` to tweak the same deployment files such that `dev` subdomains route to this home machine.

Switchboard also solves for the fact that Envoy would normally require additional containers (sidecars?) implement authentication, observability, certificate generation, etc.

# Configuration
----

Each of the Switchboard variables described below may be configured via YAML by mounting a file at `/etc/switchboard/config.yml`, or by providing an enviroment variable of the same name (except upper-case). For example, the `ingress` variable may be a string within the YML file, or an enviroment variable `INGRESS` (which takes precedence). The two strategies can be layered together, allowing for Kubernetes `kustomization` for different environments.

## Sample Kubernetes Deployment

See [my production deployment yaml](https://gist.github.com/zaneclaes/4901f9a30baa119953c1f8074390cff9).

This example assumes `kube2iam` for AWS authentication in order to achieve the S3 backup-and-restore of certbot-generated certifiactes. It also tweaks the default logging formats to structured JSON, making it well suited for a variety of ingestion pipelines. Finally, it provides samples of readiness and liveness checks.

## Optional Settings

Default values (in parenthesis).

* `http_port`: The port to listen on for HTTP connections (`8080`)
* `https_port`: The port to listen on for HTTPS connections (`8443`)
* `admin_port`: The port for the Envoy admin interface (`5000`); an empty value will disable the admin interface.
* `auth_port`: Enable `ext-authz` on the specified port (see: Authorizations)
* `bind_address`: The address on which to listen (`0.0.0.0`)
* `use_remote_address`: See [Envoy's documentation](https://www.envoyproxy.io/docs/envoy/latest/api-v2/config/filter/network/http_connection_manager/v2/http_connection_manager.proto) (default=true)
* `add_user_agent`: See [Envoy's documentation](https://www.envoyproxy.io/docs/envoy/latest/api-v2/config/filter/network/http_connection_manager/v2/http_connection_manager.proto) (default=true)
* `log_format_switchboard`: The Python `logger` format for Switchboard (`[%(asctime)s] [%(process)d] [%(levelname)s] [%(name)s] %(message)s`)
* `log_format_envoy`: The Envoy application log format (empty = Envoy default)
* `log_format_access`: The access log format for Envoy (empty = Envoy default)
* `log_format_access_json`: The JSON access log format for Envoy (empty = Envoy default)
* `log_format_auth`: either `text` or `json` (`text`)
* `log_level`: Used by both Switchboard, Envoy, and Authorization applications (`INFO`)
* `log_path`: The folder in which to write log files (empty = write to `/dev/stdout`)

## Ingress

The `ingress` variable defines the domain names which Switchboard will listen upon. The value can be an array (in a YML file) or a string with each ingress value separated by any whitespace. It is required and each value takes the form of:
`{schema}://{subdomain}:{domain}{path}@{destination}`

### Schema

The schema may be `http`, `https`, `ws`, or `wss`. For secure schemas, adding a `!` at the end will force the unsecure version to redirect to the secure. Alternatively, the `?` suffix is a conevenience to listent on both secure and unsecure schemas.

### Subdomain

This value may be empty if you do not wish to listen on a subdomain. You may also use the `?` suffix to listen on both the subdomain and the top level domain. For example, a value of `www?` would match for both `www.mydomain.com` and `mydomain.com`.

### Domain

The top-level domain name, such as `mydomain.com` or `some-domain.io`.

### Path

The `path` is optional, and will match only requests which begin with the specified path. If suffixed with a `!`, the path will be stripped before it is sent to the cluster. For example, a value of `/foo!` will mean that the destination will receive requests to `/foo/bar` as simply `/bar`.

### Destination

The `destination` can either be an `egress_name` or a fully-qualified domain name for redirection.

### Examples

* `https://www:mydomain.com@my-cluster`: Route `https://www.mydomain.com` to `my-cluster` (egress)
* `http://www?:mydomain.com@google.com`: Redirect `http://www.mydomain.com` AND `http://mydomain.com` to `google.com`
* `https!://:mydomain.com@my-cluster`: Force `https` and route `mydomain.com` to `my-cluster` (egress)
* `wss?://api:mydomain.com@my-cluster`: Support Web Socket upgrading on both `http` and `https` for `api.mydomain.com`, routed to `my-cluster`

## Egress

The `egress` variable defines your Envoy clusters (servers) to route traffic to. The value can be an array (in a YML file) or a string with each egress value separated by any whitespace. It is required and each value takes the form of:
`{egress_name}:{schema}@{address}:{port}`

The same `egress_name` can be used twice with both the `http` and `grpc` schemas in order to support both, in which case the `content-type` header value of `application/grpc` will be used to determine which destination to use. For example, the two values can be used together:

* `my-cluster:http@localhost:5200`: Route regular HTTP traffic for `my-cluster` to `localhost:5200`
* `my-cluster:grpc@localhost:5201`: Route GRPC traffic for `my-cluster` to `localhost:5201`

You can also use environment variables to assist in congfiguration. For example, in Kubernetes, you might route to some `grafana` deployment as follows:

* `grafana:http@$GRAFANA_SERVICE_HOST:$GRAFANA_SERVICE_PORT`

## Shard

If the `shard` variable is provided, all of the subdomains will be modified based upon the value provided.

Assuming that the value `dev` is provided, then the following will be true of ingress values:
* `http://www:mydomain.com:my-cluster` will instead listen on `http://dev-mydomain.com`
* `https?://:mydomain.com:my-cluster` will instead listen on `http://dev.mydomain.com`
* `wss!://test!:mydomain.com:my-cluster` will _still listen on_ `https://test.mydomain.com` (no change)

## Observability

If the `stats_type` configuration is set to `statsd`, the `statsd_exporter` will automatically be started. It will receive traffic from Envoy on port `9125` and publish metrics on port `9102`, meaning that these ports become reserved and clients like Prometheus can connect to `{IP}:9125/metrics`.

## Authorization

If the `auth_port` configuration is provided, Switchboard will automatically create a self-managed authorization server to protect access to given domains. It will look for yaml files in `/etc/switchboard/authorizations/` which match the domain name being accessed.

Note: using the `authorization` feature automatically creates a GRPC cluster named `ext-authz`, powered by an internal Go server, and checks with this server before processing any request.

## Certificate Generation

If the `https` or `wss` schema is used for any ingress, and the `email` variable is provided, Switchboard will attempt to use LetsEncrypt to generate a certificate.

### Examples

`/etc/switchboard/authorizations/example.com.yaml`:
```
bearer: ['some_token']
basic: ['dGVzdDoxMjM0']
```

Any requests to `example.com` will only be allowed to proceed with one of the two headers:

* `Authorization: Bearer some_token` (a presumed access token)
* `Authorization: Basic dGVzdDoxMjM0` (equivalent to `test:1234` as a username/password)

Requests without these headers will be rejected. Successfull requests will have the `x-ext-auth-ratelimit` set to the sha256 of the token/authorization (for use in rate-limiting). Requests to other domains will succeed without challenge.
