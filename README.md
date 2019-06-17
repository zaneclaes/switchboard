# Switchboard
----

A simple-to-configure front proxy in a docker container, built on Envoy.

## Features

* TLS termination
* GRPC
* Web Sockets
* HTTP->HTTPS redirection
* Domain name redirection
* Sharding (different subdomains for different environments)
* Automatic certificate generation via CertBot/LetsEncrypt
* Stateless (certificate backup via S3)

## Motivation

I have a Kubernetes deployment running in production which needs to route traffic from multiple different domains to different containers. I also run a development version of the same stack on my Linux computer at my house, and I want to use `kustomization` to tweak the same deployment files such that `dev` subdomains route to this home machine.

# Configuration
----

Each of the Switchboard variables described below may be configured via YAML by mounting a file at `/etc/switchboard/config.yml`, or by providing an enviroment variable of the same name (except upper-case). For example, the `ingress` variable may be a string within the YML file, or an enviroment variable `INGRESS` (which takes precedence). The two strategies can be layered together, allowing for Kubernetes `kustomization` for different environments.

## Optional Settings

Default values (in parenthesis).

* `http_port`: The port to listen on for HTTP connections (`8080`)
* `https_port`: The port to listen on for HTTPS connections (`8443`)
* `admin_port`: The port for the Envoy admin interface (`5000`); an empty value will disable the admin interface.
* `bind_address`: The address on which to listen (`0.0.0.0`)
* `log_format_switchboard`: The Python `logger` format for Switchboard (`[%(asctime)s] [%(process)d] [%(levelname)s] [%(name)s] %(message)s`)
* `log_format_envoy`: The Envoy application log format (empty = Envoy default)
* `log_format_access`: The access log format for Envoy (empty = Envoy default)
* `log_format_access_json`: The JSON access log format for Envoy (empty = Envoy default)
* `log_level`: Used by both Switchboard and Envoy applications (`INFO`)
* `log_path`: The folder in which to write log files (empty = write to `/dev/stdout`)

## Ingress

The `ingress` variable defines the domain names which Switchboard will listen upon. The value can be an array (in a YML file) or a string with each ingress value separated by any whitespace. It is required and each value takes the form of:
`{schema}://{subdomain}:{domain}{path}:{destination}`

The `destination` can either be an `egress_name` or a fully-qualified domain name for redirection.

Examples:
* `https://www:mydomain.com:my-cluster`: Route `https://www.mydomain.com` to `my-cluster` (egress)
* `http://www?:mydomain.com:google.com`: Redirect `http://www.mydomain.com` AND `http://mydomain.com` to `google.com`
* `https!://:mydomain.com:my-cluster`: Force `https` and route `mydomain.com` to `my-cluster` (egress)
* `wss?://api:mydomain.com:my-cluster`: Support Web Socket upgrading on both `http` and `https` for `api.mydomain.com`, routed to `my-cluster`

## Egress

The `egress` variable defines your Envoy clusters (servers) to route traffic to. The value can be an array (in a YML file) or a string with each egress value separated by any whitespace. It is required and each value takes the form of:
`{egress_name}:{schema}://{address}:{port}`

The same `egress_name` can be used twice with both the `http` and `grpc` schemas in order to support both, in which case the `content-type` header value of `application/grpc` will be used to determine which destination to use. For example, the two values can be used together:
* `my-cluster:http://localhost:5200`: Route regular HTTP traffic for `my-cluster` to `localhost:5200`
* `my-cluster:grpc://localhost:5201`: Route GRPC traffic for `my-cluster` to `localhost:5201`

## Shard

If the `shard` variable is provided, all of the subdomains will be modified based upon the value provided.

Assuming that the value `dev` is provided, then the following will be true of ingress values:
* `http://www:mydomain.com:my-cluster` will instead listen on `http://dev-mydomain.com`
* `https?://:mydomain.com:my-cluster` will instead listen on `http://dev.mydomain.com`
* `wss!://test!:mydomain.com:my-cluster` will _still listen on_ `https://test.mydomain.com` (no change)

## Certificate Generation

If the `https` or `wss` schema is used for any ingress, and the `email` variable is provided, Switchboard will attempt to use LetsEncrypt to generate a certificate.
