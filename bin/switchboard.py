#!/usr/bin/env python
import yaml, json, configparser, os, subprocess, re

def _file_access_log(router_name, path = "/dev/stdout"):
  return {
    "name": "envoy.file_access_log",
    "config": {
      # https://www.envoyproxy.io/docs/envoy/latest/configuration/access_log#config-access-log-format-dictionaries
      # Optimized for Datadog logging.
      "path": path,
      "json_format": {
          "@timestamp": "%START_TIME%",
          "processor": "net",
          "router": router_name,
          "duration": "%DURATION%",
          "http.method": "%REQ(:METHOD)%",
          "http.url": "%REQ(X-FORWARDED-PROTO)%://%REQ(:AUTHORITY)%%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%",
          "http.protocol": "%PROTOCOL%",
          "http.status_code": "%RESPONSE_CODE%",
          "http.useragent": "%REQ(USER-AGENT)%",
          "http.request_id": "%REQ(X-REQUEST-ID)%",
          "http.response_flags": "%RESPONSE_FLAGS%",
          "http.referer": "%REQ(REFERER)%",
          "network.destination.ip": "%UPSTREAM_HOST%",
          "network.destination.cluster": "%UPSTREAM_CLUSTER%",
          "network.destination.duration": "%RESP(X-ENVOY-UPSTREAM-SERVICE-TIME)%",
          "network.client.ip": "%REQ(X-FORWARDED-FOR)%",
          "network.bytes_read": "%BYTES_RECEIVED%",
          "network.bytes_written": "%BYTES_SENT%",
          "grpc_status": "%RESP(GRPC-STATUS)%"
        }
      }
    }

def sh(cmd, print_cmd = True):
  proc = subprocess.Popen(cmd, shell=True)
  comm = proc.communicate()

  if proc.returncode != 0:
    raise Exception('[Shell] [ERROR]', comm)
    exit(-1)

  return comm[0]

# Route traffic (within a virtual host) to a specific cluster.
route_match_dest_schema_settings = {
  'http': {},
  'https': {},
  'grpc': {'headers': { "name": "content-type", "exact_match": "application/grpc" } }
}
def _match_route(dest_schema, path_prefix = '/'):
  ret = dict(route_match_dest_schema_settings[dest_schema])
  ret['prefix'] = path_prefix
  return ret

def _route_cluster(match, cluster_name):
  return { "match": match, "route": { "cluster": cluster_name } }

def _route_redirect(match, target):
  return { 'match': match, 'redirect': { 'host_redirect': target } }

def _certificate(domain):
  if not os.path.isdir('/etc/letsencrypt'):
    print("[WARN] skipping _certificate for %s" % domain)
    return {}
  if not os.path.isdir('/etc/letsencrypt/renewal'):
    sh('/usr/local/bin/certsync.sh restore')
  sh('/usr/local/bin/certbot.sh ' + domain)
  if not os.path.isdir('/etc/letsencrypt/live/' + domain):
    raise Exception("Failed to get a certificate for " + domain)
  # Back up with every cert creation, so that intermediate progress is saved
  # In the case there are lots of certs, this can be a useful trait if containers
  # are killed by some health check daemon.
  with open('/var/log/letsencrypt/letsencrypt.log', 'r') as lf:
    log = lf.read()
    if not "not yet due" in log:
      print("[Balancer] backing up certbot:\n%s\n------" % log)
      sh('/usr/local/bin/certsync.sh backup')
  os.rename('/var/log/letsencrypt/letsencrypt.log', '/var/log/letsencrypt/%s.log' % domain)
  return {
    "certificate_chain": { "filename": "/etc/letsencrypt/live/%s/fullchain.pem" % domain },
    "private_key": { "filename": "/etc/letsencrypt/live/%s/privkey.pem" % domain }
  }

def _shard_subdomain(subdomain):
  shard = os.getenv('SHARD', '')
  if len(shard) <= 0: return subdomain
  if len(subdomain) <= 0: return shard
  return "%s-%s" % (shard, subdomain)

# may return [fqdn, domain], or [domain], or ["*"]
def _get_fqdns(subdomain, domain):
  sharded = _shard_subdomain(subdomain)
  domains = []
  if len(sharded) > 0: domains += ["%s.%s" % (sharded, domain)]
  elif len(subdomain) <= 0: domains += [domain]
  if len(domains) <= 0: domains = ["*"]
  return domains

# assumes first fqdn is most unique, and may be used for naming purposes
def _virtual_host(fqdns, routes):
  return { "domains": fqdns, "name": "vh-" + fqdns[0], "routes": routes }

def _filter_http_connection_manager(router_name, virtual_hosts = []):
  config = {
    'codec_type': 'AUTO',
    'stat_prefix': 'ingress_http',
    'add_user_agent': True,
    'use_remote_address': True,
    'access_log': [_file_access_log(router_name)],
    'http_filters': { 'name': 'envoy.router' },
    'route_config': { 'virtual_hosts': virtual_hosts }
  }
  return { 'name': 'envoy.http_connection_manager', 'config': config }

def _http_vh_filters(router_name, virtual_hosts):
  return [{ 'filters': _filter_http_connection_manager(router_name, virtual_hosts) }]

def _https_tls_filter_chain_match(fqdns, domain, routes):
  router_name = '-'.join(['https'] + fqdns)
  return {
    'filter_chain_match': { "server_names": fqdns },
    'filters': _filter_http_connection_manager(router_name, [_virtual_host(fqdns, routes)]),
    'tls_context': {
      'common_tls_context': {
        'alpn_protocols': 'h2',
        'tls_certificates': [_certificate(domain)]
      }
    }
  }

def _socket_address(address, port):
  return { 'socket_address': { 'address': address, 'port_value': port } }

def _ingress_address(ingress_type):
  return _socket_address(bind_address, ingress_ports[ingress_type])

def _admin():
  return { 'access_log_path': '/dev/stdout', 'address': _ingress_address('admin') }

def _endpoints(address, port):
  return { 'lb_endpoints': [{'endpoint': { 'address': _socket_address(address, port) } }] }

# --------------------------------
# Clusters
# --------------------------------
default_cluster_settings = {
  'type': 'LOGICAL_DNS', 'dns_lookup_family': 'V4_ONLY', 'lb_policy': 'ROUND_ROBIN',
  'load_assignment': []
}
cluster_schema_settings = {
  'http': { 'connect_timeout': '0.25s' },
  'grpc': { 'connect_timeout': '25s', 'http2_protocol_options': {} }
}

def _cluster(schema, name, address, port):
  cd = dict(default_cluster_settings) # Copy default cluster settings
  cd['name'] = name
  if not schema in cluster_schema_settings:
    raise Exception("{0} is not a cluster schema ({1})".format(schema, cluster_schema_settings))
  cd.update(cluster_schema_settings[schema]) # Add settings specific to this schema type
  cd['load_assignment'] = { 'cluster_name': name, 'endpoints': _endpoints(address, port) }
  return cd

# --------------------------------
# Listeners
# --------------------------------
listener_schema_settings = {
  'http': {
    'listener_filters': []
  },
  'https': {
    'listener_filters': [{'name': 'envoy.listener.tls_inspector', 'config': {}}]
  }
}
def _listener(schema, filter_chains):
  listener = dict(listener_schema_settings[schema]) # Copy default listener settings
  listener['name'] = schema
  if not schema in listener_schema_settings:
    raise Exception("{0} is not a listener schema ({1})".format(schema, listener_schema_settings))
  listener['address'] = _ingress_address(schema)
  if "USE_PROXY_PROTOCOL" in os.environ:
    listener['listener_filters'] += [{'name': 'envoy.listener.proxy_protocol'}]
  listener['filter_chains'] = filter_chains
  return listener

# --------------------------------
# Main
# --------------------------------
def _arr_env(name):
  ls = re.split(r'(\s+)', os.getenv(name, ''))
  return [x.strip() for x in ls if x.strip()]

# Re pattern groups
re_schema = "(?P<schema>[\w\?]+)"
re_domain = "(?P<domain>[\.a-z0-9-]*)"
re_redirect = "(?P<redirect>[\.a-z0-9-]+)"
re_subdomain = "(?P<subdomain>[a-z0-9-]*)"
re_dest = "(?P<dest>[a-z0-9-]+)"
re_port = "(?P<port>[0-9]+)"

if __name__ == "__main__":
  bind_address = os.getenv('BIND_ADDRESS', '0.0.0.0')
  ingress_ports = {
    'admin': os.getenv('ADMIN_PORT', 5000),
    'http': os.getenv('HTTP_PORT', 8080),
    'https': os.getenv('HTTPS_PORT', 8443)
  }

  http_default_cluster_name = os.getenv('DEFAULT_CLUSTER', '')
  print("Default Cluster", http_default_cluster_name)
  virtual_hosts = _arr_env('VIRTUAL_HOSTS')
  print("Virtual Hosts", virtual_hosts)
  destinations = _arr_env('CLUSTERS')
  print("Clusters", destinations)

  # Build Destionations
  dest_clusters = {}
  dest_schemas = {}
  dest_re_str_match = re.compile(
    "^{0}://{1}:{2}:{3}$".format(re_schema, re_dest, re_domain, re_port))
  for dest_str in destinations:
    dest_match = dest_re_str_match.match(dest_str)
    if not dest_match:
      print("[WARN] No match for destination config str: %s" % dest_match)
      continue
    dest_schema = dest_match.group('schema')
    dest_name = dest_match.group('dest')
    cluster_name = "%s-%s" % (dest_schema, dest_name)
    if not dest_name in dest_schemas: dest_schemas[dest_name] = []
    dest_schemas[dest_name] += [dest_schema]
    dest_clusters[cluster_name] = _cluster(
      dest_schema,
      cluster_name,
      dest_match.group('domain'),
      dest_match.group('port'),
    )

  # print("redirections", json.dumps(redirections, indent=2))
  # print("clusters", json.dumps(dest_clusters, indent=2))

  # Build Virtual Hosts
  vh_re_str_match = re.compile(
    "^{0}://{1}:{2}:{3}$".format(re_schema, re_subdomain, re_domain, re_redirect))
  listener_filter_chain_matches = { 'http': [], 'https': [] }
  http_virtual_hosts = []
  https_filter_chains = []

  for vh_str in virtual_hosts: # Iterate virtual hosts
    vh_match = vh_re_str_match.match(vh_str)
    if not vh_match:
      print("[WARN] No match for virtual host config str: %s" % vh_str)
      continue
    if vh_match.group('schema') == 'https?': schemas = ['http', 'https']
    else: schemas = [vh_match.group('schema')]
    for listener_schema in schemas:
      routes = []
      subdomain = vh_match.group('subdomain')
      domain = vh_match.group('domain')
      fqdns = _get_fqdns(subdomain, domain)
      redirect = vh_match.group('redirect')
      if '.' in redirect: # Domain - level redirect
        print("redirect %s%s to %s" % (listener_schema, fqdns, vh_match.group('redirect')))
        match = _match_route(listener_schema)
        routes += [_route_redirect(match, vh_match.group('redirect'))]
      else: # Probably a cluster?
        dest_name = redirect
        if not dest_name in dest_schemas:
          raise Exception("%s was not registered as a cluster" % (dest_name))
        for dest_schema in dest_schemas[dest_name]:
          cluster_name = "%s-%s" % (dest_schema, dest_name)
          match = _match_route(dest_schema)
          if cluster_name in dest_clusters:
            print("route %s%s to %s" % (listener_schema, fqdns, cluster_name))
            routes += [_route_cluster(match, cluster_name)]
          else:
            raise Exception("%s was not a redirection or cluster" % cluster_name)
        # End dest_schema loop

      if listener_schema == 'https':
        https_filter_chains += [_https_tls_filter_chain_match(fqdns, domain, routes)]
      elif listener_schema == 'http':
        http_virtual_hosts += [_virtual_host(fqdns, routes)]
      else:
        raise Exception("do not know how to configure %s routes" % listener_schema)

  if len(http_default_cluster_name) > 0:
    routes = [_route_cluster(_match_route('http'), 'http-' + http_default_cluster_name)]
    http_virtual_hosts += [_virtual_host(["*"], routes)]

  listeners = []
  if len(http_virtual_hosts) > 0:
    listeners += [_listener('http', _http_vh_filters('http', http_virtual_hosts))]
    print("binding http://%s:%s" % (bind_address, ingress_ports['http']))

  if len(https_filter_chains) > 0:
    listeners += [_listener('https', https_filter_chains)]
    print("binding https://%s:%s" % (bind_address, ingress_ports['https']))

  if len(listeners) <= 0: raise Exception("No listeners created.")

  resources = { 'listeners': listeners, 'clusters': list(dest_clusters.values()) }
  data = { "static_resources": resources, "admin": _admin() }
  with open('envoy.yaml', 'w') as outfile:
    yaml.dump(data, outfile, default_flow_style=False)
