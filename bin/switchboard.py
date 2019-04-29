#!/usr/bin/env python
import yaml, json, configparser, os, subprocess, re, logging
from collections import defaultdict

domain_tls = {}

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

  return comm[0]

# Route traffic (within a virtual host) to a specific cluster.
def _match_route(dest_schema, path_prefix = '/', match_options = {}):
  ret = dict(match_options)
  if dest_schema == 'grpc':
    ret['headers'] = { "name": "content-type", "exact_match": "application/grpc" }
  ret['prefix'] = path_prefix
  return ret

def _match_routes_egress(listener_schema, dest_name, route_options = {}):
  if '.' in dest_name:
    log.info(f"match egress host_redirect {listener_schema} to {dest_name}")
    return [{ 'match': _match_route(listener_schema), 'redirect': { 'host_redirect': dest_name } }]
  if not dest_name in dest_schemas:
    raise Exception(f"{dest_name} was not registered as an egress point")
  routes = []
  for dest_schema in dest_schemas[dest_name]:
    cluster_name = f"{dest_schema}-{dest_name}"
    match = _match_route(dest_schema)
    if not cluster_name in dest_clusters:
      raise Exception(f"{cluster_name} was not a redirection or cluster")
    log.info(f"match egress route {listener_schema} to cluster {dest_schema}://{cluster_name}")
    route = dict(route_options)
    route['cluster'] = cluster_name
    routes.append({ 'match': _match_route(dest_schema), 'route': route })
  return routes

def _certificate(domain):
  if domain in domain_tls: # Use cached version.
    logging.info(f'certificate already generated for {domain}')
    return domain_tls[domain]

  le_dir = '/etc/letsencrypt'
  if not os.path.isdir(le_dir):
    logging.warn(f"skipping _certificate for {domain}")
    return {}
  if not os.path.isdir(f'{le_dir}/renewal'):
    sh('/usr/local/bin/certsync.sh restore')

  email = cfg['email']
  if len(email) <= 0:
    logging.warn(f"cannot generate a certificate for {domain} because no email provided")
    return {}

  fn_renew = f"{le_dir}/renewal/{domain}.conf"
  cb_flags = '--dns-route53 -q'
  if os.path.isfile(fn_renew):
    logging.info(f'renewing certificate for {domain}...')
    sh(f'certbot renew {cb_flags}')#  --post-hook "sudo service nginx reload"
  else:
    logging.info(f'requesting certificate for {domain}')
    sh(
      f'certbot certonly {cb_flags} -d \"*.{domain}\" -d {domain} -m {email} ' +
      '--server https://acme-v02.api.letsencrypt.org/directory --agree-tos --non-interactive'
    )

  if not os.path.isdir('/etc/letsencrypt/live/' + domain):
    raise Exception("Failed to get a certificate for " + domain)
  # Back up with every cert creation, so that intermediate progress is saved
  # In the case there are lots of certs, this can be a useful trait if containers
  # are killed by some health check daemon.
  with open('/var/log/letsencrypt/letsencrypt.log', 'r') as lf:
    log = lf.read()
    if not "not yet due" in log:
      logging.info(f"backing up certbot")
      sh('/usr/local/bin/certsync.sh backup')
  os.rename('/var/log/letsencrypt/letsencrypt.log', '/var/log/letsencrypt/%s.log' % domain)
  domain_tls[domain] = {
    "certificate_chain": { "filename": "/etc/letsencrypt/live/%s/fullchain.pem" % domain },
    "private_key": { "filename": "/etc/letsencrypt/live/%s/privkey.pem" % domain }
  }
  return domain_tls[domain]

def _shard(shard, subdomain, domain):
  # calculate `sharded`, the _real_ subdomain value
  if len(shard) <= 0: sharded = subdomain
  elif len(subdomain) <= 0: sharded = shard
  else: sharded = f"{shard}-{subdomain}"
  # apply the subdomain, or just return the domain
  if len(sharded) > 0: return f"{sharded}.{domain}"
  else: return domain

# may return [fqdn, domain], or [domain], or ["*"]
def _get_fqdns(match):
  subdomain = match.group('subdomain')
  domain = match.group('domain')
  shard = cfg['shard']
  if match.group('subdomain_no_shard'): shard = ''

  fqdns = set([_shard(shard, subdomain, domain)])
  if match.group('subdomain_opt'): fqdns.add(_shard(shard, '', domain))
  if len(fqdns) <= 0: fqdns.add('*')
  return list(fqdns)

# assumes first fqdn is most unique, and may be used for naming purposes
def _virtual_host(fqdns, routes):
  return { "domains": fqdns, "name": "vh-" + fqdns[0], "routes": routes }

def _filter_http_connection_manager(router_name, virtual_hosts = [], config = {}):
  config.update({
    'codec_type': 'AUTO',
    'stat_prefix': 'ingress_http',
    'add_user_agent': True,
    'use_remote_address': True,
    'access_log': [_file_access_log(router_name)],
    'http_filters': { 'name': 'envoy.router' },
    'route_config': { 'virtual_hosts': virtual_hosts }
  })
  return { 'name': 'envoy.http_connection_manager', 'config': config }

def _vh_filter_chain_match(router_name, virtual_hosts, config = {}):
  return [{ 'filters': _filter_http_connection_manager(router_name, virtual_hosts, config) }]

def _https_tls_filter_chain_match(fqdns, domain, routes, config = {}):
  router_name = '-'.join(['https'] + fqdns)
  return {
    'filter_chain_match': { "server_names": fqdns },
    'filters': _filter_http_connection_manager(router_name, [_virtual_host(fqdns, routes)], config),
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
  return _socket_address(cfg['bind_address'], cfg[f"{ingress_type}_port"])

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

def _listener(schema, filter_chains):
  listener = { 'name': schema, 'address': _ingress_address(schema), 'filter_chains': filter_chains }
  if "USE_PROXY_PROTOCOL" in os.environ:
    if not 'listener_filters' in listener: listener['listener_filters'] = []
    listener['listener_filters'] += [{'name': 'envoy.listener.proxy_protocol'}]
  if schema == 'https':
    if not 'listener_filters' in listener: listener['listener_filters'] = []
    listener['listener_filters'] += [{'name': 'envoy.listener.tls_inspector', 'config': {}}]
  return listener

# --------------------------------
# Main
# --------------------------------
def str2list(string):
  if type(string) is list: return string
  return [x.strip() for x in re.split(r'(\s+)', string) if x.strip()]

# Combine an environment variable with the contents of any files into a single set of values
# i.e., passing 'ingress' will look at the INGRESS env. var and /etc/switchboard/ingress/**
def get_uniq_config_values(name):
  ret = set(str2list(os.getenv(name.upper(), '')))
  d = '/etc/switchboard/' + name
  if os.path.isdir(d):
    for fn in os.listdir(d):
      if not os.path.isfile(os.path.join(d, fn)): continue
      with open(os.path.join(d, fn), 'r') as f:
        ret = ret.union(set(str2list(f.read())))
  return ret

def _re_param(name, pattern):
  return f"(?P<{name}>{pattern})"

# Ingress regex
re_ingress_schema = "".join([
  _re_param("schema", "\w+"),
  _re_param("schema_opt", "\??"), # If ends with ?, listen on both secure and insecure
  _re_param("schema_req", "\!?") # If ends with !, enforce this schema (redirect http to https)
])
re_ingress_subdomain = "".join([
  _re_param("subdomain", "[a-z0-9-]*"),
  _re_param("subdomain_opt", "\??"), # If ends with ?, also listen on no-subdomain version
  _re_param("subdomain_no_shard", "\!?"), # If ends with !, consider final: do not apply sharding.
])
re_ingress_domain = _re_param("domain", "[\.a-z0-9-]*")
re_ingress_dest = _re_param("dest", "[\.a-z0-9-]+")
re_ingress = f"^{re_ingress_schema}://{re_ingress_subdomain}:{re_ingress_domain}:{re_ingress_dest}$"
re_ingress_matcher = re.compile(re_ingress)

# Egress Regex
re_egress_dest = _re_param("dest", "[a-z0-9-]+")
re_egress_schema = _re_param("schema", "\w+")
re_egress_domain = _re_param("domain", "[\.a-z0-9-]*")
re_egress_port = _re_param("port", "[0-9]+")
re_egress = f"^{re_egress_dest}:{re_egress_schema}://{re_egress_domain}:{re_egress_port}$"
re_egress_matcher = re.compile(re_egress)

if __name__ == "__main__":
  cfg = {
    'log_format': '[%(asctime)s] [%(process)d] [%(levelname)s] [%(name)s] %(message)s',
    'log_level': 'INFO',
    'bind_address': '0.0.0.0',
    'admin_port': 5000,
    'http_port': 8080,
    'https_port': 8443,
    'default_route': '',
    'shard': '',
    'email': '',
  }
  if os.path.isfile('/etc/switchboard/config.yml'):
    with open('/etc/switchboard/config.yml', 'r') as stream:
      cfg.update(yaml.safe_load(stream))
  for var_name in cfg:
    cfg[var_name] = os.getenv(var_name.upper(), cfg[var_name])

  logging.basicConfig(format=cfg['log_format'], level=cfg['log_level'])

  ingress_values = get_uniq_config_values('ingress')
  logging.debug(f"Ingress Regex: {re_ingress}")
  logging.debug(f"Ingress Config: {ingress_values}")

  destinations = get_uniq_config_values('egress')
  logging.debug(f"Egress Regex: {re_egress}")
  logging.debug(f"Egress Config: {destinations}")

  # [Egress] Build Routes
  dest_clusters = {}
  dest_schemas = defaultdict(set)
  for dest_str in destinations:
    log = logging.getLogger(f"<egress>{dest_str}")
    dest_match = re_egress_matcher.match(dest_str)
    if not dest_match:
      raise Exception(f"No regex match for egress config str: {dest_str}")

    dest_schema = dest_match.group('schema')
    dest_name = dest_match.group('dest')
    cluster_name = "%s-%s" % (dest_schema, dest_name)
    if cluster_name in dest_clusters:
      raise Exception(f"The cluster {cluster_name} has already been defined")
    log.info(f'creating cluster {cluster_name}')
    dest_schemas[dest_name].add(dest_schema)
    cluster = _cluster(
      dest_schema,
      cluster_name,
      dest_match.group('domain'),
      dest_match.group('port'),
    )
    log.debug(f"cluster {cluster_name}: {cluster}")
    dest_clusters[cluster_name] = cluster
  # [Egress] End Routes

  # [Ingress] Build Virtual Hosts
  listener_filter_chain_matches = { 'http': [], 'https': [] }
  listener_virtual_hosts = { 'http': [], 'ws': [] }
  https_filter_chains = []

  for ingress_str in ingress_values: # Iterate virtual hosts
    log = logging.getLogger(f"<ingress>{ingress_str}")
    ingress_match = re_ingress_matcher.match(ingress_str)
    if not ingress_match:
      raise Exception(f"No regex match for ingress config str: {ingress_str}")

    ingress_schema_str = ingress_match.group('schema')
    domain = ingress_match.group('domain')
    fqdns = _get_fqdns(ingress_match)
    dest_name = ingress_match.group('dest')
    filter_config = {}
    if ingress_schema_str == 'wss': # Allow for simple upgrading of connection when HTTPS
      filter_config['upgrade_configs'] = [{ 'upgrade_type': 'websocket' }]
      ingress_schema_str = 'https'
    if ingress_match.group('schema_req'): # Configure a http -> https redirect
      log.info(f"redirect to secure for {ingress_schema_str}{fqdns}")
      routes = [{ 'match': _match_route('http'), 'redirect': { 'https_redirect': True } }]
      listener_virtual_hosts['http'].append(_virtual_host(fqdns, routes))
      ingress_schema_str = 'https'

    # Build a finalized set of schemas which will be listened upon
    ingress_schemas = set([ingress_schema_str])
    if ingress_match.group('schema_opt'): # Listen on both secure and insecure
      log.info(f"listen on both insecure and secure for {ingress_schema_str}{fqdns}")
      if not ingress_schema_str == 'https':
        raise Exception(f"Only https schema may be optional")
      ingress_schemas.add('http')

    for listener_schema in ingress_schemas:
      log.info(f"ingress {listener_schema} {fqdns} => {dest_name}")
      routes = _match_routes_egress(listener_schema, dest_name)

      log.debug(f'listener {listener_schema} with routes {routes}')
      if listener_schema == 'https':
        https_filter_chains.append(
          _https_tls_filter_chain_match(fqdns, domain, routes, filter_config))
      elif listener_schema in listener_virtual_hosts:
        listener_virtual_hosts[listener_schema].append(_virtual_host(fqdns, routes))
      else:
        raise Exception(f"do not know how to configure {listener_schema} routes")
  # End Virtual Hosts

  if len(cfg['default_route']) > 0:
    logging.info("Default HTTP Route: " + cfg['default_route'])
    routes = _match_routes_egress('http', cfg['default_route'])
    listener_virtual_hosts['http'].append(_virtual_host(["*"], routes))

  logging.debug("virtual hosts: " + json.dumps(listener_virtual_hosts, indent=2))
  logging.debug("filter chains: " + json.dumps(https_filter_chains, indent=2))

  listeners = []
  if len(https_filter_chains) > 0:
    # Redirect unmatched HTTPS back to HTTP...
    route_http = { 'match': _match_route('https'), 'redirect': { 'scheme_redirect': 'http' } }
    https_filter_chains += _vh_filter_chain_match('https', [_virtual_host(["*"], route_http)])
    listeners += [_listener('https', https_filter_chains)]
    logging.info("[bind] https://%s:%s" % (cfg['bind_address'], cfg['https_port']))

  for schema in listener_virtual_hosts:
    if len(listener_virtual_hosts[schema]) <= 0: continue
    vhs = listener_virtual_hosts[schema]
    filter_config = {}
    if schema == 'ws':
      filter_config['upgrade_configs'] = [{ 'upgrade_type': 'websocket' }]
    listeners.append(_listener(schema, _vh_filter_chain_match(schema, vhs, filter_config)))
    logging.info("[bind] %s://%s:%s" % (schema, cfg['bind_address'], cfg['http_port']))

  if len(listeners) <= 0: raise Exception("No listeners created.")

  resources = { 'listeners': listeners, 'clusters': list(dest_clusters.values()) }
  data = { "static_resources": resources, "admin": _admin() }
  with open('envoy.yaml', 'w') as outfile:
    yaml.dump(data, outfile, default_flow_style=False)
