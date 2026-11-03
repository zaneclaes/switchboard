#!/usr/bin/env python3
import yaml, json, os, subprocess, re, logging, time, shutil, sys, ipaddress
from collections import defaultdict

domain_tls = {}
new_certs = []
certbot_renewal = None

# --------------------------------------------------------------------------------------------------
# Regex Definitions
# --------------------------------------------------------------------------------------------------
def _re_param(name, pattern):
  return f"(?P<{name}>{pattern})"

le_dir = '/etc/letsencrypt'
le_fnz = '/etc/letsencrypt.zip'

re_certbot_filename = _re_param("name", r"\w+")
re_certbot_version = _re_param("version", r"\d+")
re_certbot_pem_matcher = re.compile(rf"^{re_certbot_filename}{re_certbot_version}\.pem$")

# Ingress regex
re_in_schema = "".join([
  _re_param("schema", r"\w+"),
  _re_param("schema_opt", r"\??"), # If ends with ?, listen on both secure and insecure
  _re_param("schema_req", r"\!?") # If ends with !, enforce this schema (redirect http to https)
])
re_in_subdomain = "".join([
  _re_param("subdomain", r"(?:\*|[a-z0-9-]*)"),
  _re_param("subdomain_opt", r"\??"), # If ends with ?, also listen on no-subdomain version
  _re_param("subdomain_no_shard", r"\!?"), # If ends with !, consider final: do not apply sharding.
])
re_in_domain = _re_param("domain", r"[\.a-z0-9-]+")
re_in_path = "".join([
  _re_param("path", r"[\.\/A-Za-z0-9-]*"),
  _re_param("strip_path", r"\!?") # If ends with !, strip the path prefix
])
re_in_dest = _re_param("dest", r"[\.a-z0-9-]+")
re_ingress = f"^{re_in_schema}://{re_in_subdomain}:{re_in_domain}{re_in_path}@{re_in_dest}$"
re_in_matcher = re.compile(re_ingress)

# Egress Regex
re_eg_dest = _re_param("dest", "[a-z0-9-]+")
re_eg_schema = _re_param("schema", r"\w+")
re_eg_domain = _re_param("domain", r"[\.a-z0-9-]+")
re_eg_port = _re_param("port", "[0-9]+")
re_egress = f"^{re_eg_dest}:{re_eg_schema}@{re_eg_domain}:{re_eg_port}$"
re_eg_matcher = re.compile(re_egress)

# --------------------------------------------------------------------------------------------------

def _file_access_log(router_name):
  if len(cfg['log_path']) > 0: path = '%s/%s.log' % (cfg['log_path'], router_name)
  else: path = '/dev/stdout'
  ret = _access_log_file(path)
  ret['filter'] = { 'not_health_check_filter': {} }

  if len(cfg['log_format_access']) > 0:
    ret['typed_config']['log_format'] = { 'text_format_source': {
      'inline_string': cfg['log_format_access'].replace('%ROUTER%', router_name) } }
  elif len(cfg['log_format_access_json']) > 0:
    ret['typed_config']['log_format'] = { 'json_format': _untyped_json_format(json.loads(
      cfg['log_format_access_json'].replace('%ROUTER%', router_name))) }

  return ret

# Envoy >= 1.3x renders a json_format value that is a single operator as a typed value (1, null)
# rather than a string ("1", "-"), as 1.12 did. Appending an operator which renders an empty string
# keeps the old all-strings output that log consumers (Datadog, Home Assistant) already parse.
empty_env_var = 'SWITCHBOARD_EMPTY'
def _untyped_json_format(fmt):
  if isinstance(fmt, dict): return { k: _untyped_json_format(v) for k, v in fmt.items() }
  if isinstance(fmt, str) and '%' in fmt: return fmt + f'%ENVIRONMENT({empty_env_var})%'
  return fmt

def _access_log_file(path):
  return {
    'name': 'envoy.access_loggers.file',
    'typed_config': {
      '@type': 'type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog',
      'path': path,
    }
  }

def sh(cmd):
  ret = subprocess.run(cmd, shell=True, check=False, capture_output=True, text=True)
  stdout = ret.stdout.strip()
  stderr = ret.stderr.strip()
  if ret.returncode != 0:
    raise Exception(f'Failed to run {cmd} because:\nstdout: "{stdout}"\nstderr: "{stderr}"')
  return stdout

# Start a long-running helper process. (Not sh(): it would wait forever on the inherited pipes.)
def spawn(cmd):
  logging.debug(f'spawning {cmd}')
  return subprocess.Popen(cmd, shell=True)

# Route traffic (within a virtual host) to a specific cluster.
def _match_route(base, dest_schema, prefix = '/', match_options = {}):
  ret = dict(base)
  ret['match'] = dict(match_options)
  if dest_schema == 'grpc':
    ret['match']['headers'] = [{ "name": "content-type", "string_match": { "exact": "application/grpc" } }]
  ret['match']['prefix'] = prefix
  return ret

def _match_redirect(redirect, dest_schema, prefix = '/', match_options = {}):
  return _match_route({ 'redirect': redirect }, dest_schema, prefix, match_options)

def _match_routes_egress(listener_schema, dest_name, path_prefix = '/', route_options = {}):
  if '.' in dest_name:
    log.info(f"match egress host_redirect {listener_schema} to {dest_name}")
    return [_match_redirect({ 'host_redirect': dest_name }, listener_schema, path_prefix)]
  if not dest_name in dest_schemas:
    raise Exception(f"{dest_name} was not registered as an egress point")
  routes = []
  schemas = list(dest_schemas[dest_name])
  if 'http' in schemas:
    # HTTP has no match predicates (default) and should be at the end.
    schemas.append(schemas.pop(schemas.index('http')))
  for dest_schema in schemas:
    cluster_name = f"{dest_schema}-{dest_name}"
    if not cluster_name in dest_clusters:
      raise Exception(f"{cluster_name} was not a redirection or cluster")
    log.info(f"match egress route {listener_schema} to cluster {dest_schema}://{cluster_name}")
    route = dict(route_options)
    route['cluster'] = cluster_name
    route['timeout'] = f"{cfg['timeout']}s"
    routes.append(_match_route({ 'route': route }, dest_schema, path_prefix))
  return routes

def _certificate(domain):
  global certbot_renewal, new_certs, domain_tls

  if domain in domain_tls: # Use cached version.
    logging.info(f'[certbot] certificate already generated for {domain}')
    return domain_tls[domain]

  if cfg['validate_only']:
    return _validation_certificate(domain)

  s3z = f"s3://{cfg['s3_bucket']}/{cfg['backup']}.zip" if len(cfg['s3_bucket']) > 0 else None
  if not os.path.isdir(le_dir):
    logging.warning(f"[certbot] skipping _certificate for {domain}")
    return {}
  if s3z and not os.path.isdir(f'{le_dir}/renewal'):
    logging.info(f'[certbot] restoring certificates from {s3z}')
    try:
      logging.info(f'[certbot] downloading {s3z} to {le_fnz}')
      sh(f'aws s3 cp "{s3z}" "{le_fnz}"')
      logging.info(f'[certbot] downloaded {le_fnz}')
      sh(f'unzip -q -o "{le_fnz}" -d "{le_dir}"')
      logging.info(f'[certbot] unzipped {le_fnz} to dir {le_dir}')
    except Exception as e:
      logging.error(f'[certbot] {e}')
    if os.path.isdir(f'{le_dir}/live'):
      logging.info(f'[certbot] live dir {le_dir}/live')
      for dname in os.listdir(f'{le_dir}/live'): # Enumerate the sites in the live directory
        live_dir = os.path.join(f'{le_dir}/live', dname)
        archive_dir = f'{le_dir}/archive/{dname}'
        if not os.path.isdir(live_dir): continue
        logging.info(f'[certbot] linking certificates for {dname}')
        file_versions = defaultdict(int)
        # Enumerate all files in the archive and get the latest version for each
        for fname in os.listdir(archive_dir):
          match = re_certbot_pem_matcher.match(fname)
          if not match: continue
          v = int(match.group('version'))
          if v < file_versions[match.group('name')]: continue
          file_versions[match.group('name')] = v
        # Symlink the latest versions of the files
        for fname in file_versions:
          v = file_versions[fname]
          src = f'{archive_dir}/{fname}{v}.pem'
          dst = f'{live_dir}/{fname}.pem'
          logging.debug(f'[certbot] symlinking {src} to {dst}')
          sh(f'rm -rf {dst} && ln -s "{src}" "{dst}"')

  email = cfg['email']
  if len(email) <= 0:
    logging.warning(f"[certbot] cannot generate a certificate for {domain}: no email provided")
    return {}

  fn_renew = f"{le_dir}/renewal/{domain}.conf"
  cb_flags = '--dns-route53' # --post-hook "sudo service nginx reload"
  if not os.path.isfile(fn_renew):
    new_certs.append(domain)
    logging.info(f'[certbot] requesting certificate for {domain}')
    sh(f'rm -rf {le_dir}/archive/{domain} || true')
    sh(f'rm -rf {le_dir}/live/{domain} || true')
    sh(
      f'certbot certonly {cb_flags} -d \"*.{domain}\" -d {domain} -m {email} ' +
      '--server https://acme-v02.api.letsencrypt.org/directory --agree-tos --non-interactive'
    )

  if not os.path.isdir(f'{le_dir}/live/' + domain):
    logging.error("[certbot] failed to get a certificate for " + domain)
    # raise Exception("Failed to get a certificate for " + domain)
  if os.path.isfile('/var/log/letsencrypt/letsencrypt.log'):
      shutil.move('/var/log/letsencrypt/letsencrypt.log', f'{le_dir}/{domain}.log') # may cross devices
  domain_tls[domain] = {
    "certificate_chain": { "filename": f"{le_dir}/live/{domain}/fullchain.pem" },
    "private_key": { "filename": f"{le_dir}/live/{domain}/privkey.pem" }
  }
  return domain_tls[domain]

# VALIDATE_ONLY: use the real certificate if it is on disk, else a throwaway self-signed one,
# so that `envoy --mode validate` can load the TLS contexts without certbot or S3.
def _validation_certificate(domain):
  live = f'{le_dir}/live/{domain}'
  if not os.path.isfile(f'{live}/fullchain.pem'):
    live = f'/tmp/switchboard-validate/{domain}'
    os.makedirs(live, exist_ok=True)
    sh(f'openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN={domain}" ' +
       f'-keyout "{live}/privkey.pem" -out "{live}/fullchain.pem"')
  domain_tls[domain] = {
    "certificate_chain": { "filename": f"{live}/fullchain.pem" },
    "private_key": { "filename": f"{live}/privkey.pem" }
  }
  return domain_tls[domain]

# Back up the certificates to s3
def _backup_certs():
  s3z = f"s3://{cfg['s3_bucket']}/{cfg['backup']}.zip" if len(cfg['s3_bucket']) > 0 else None

  logging.info(f"[certbot] backing up letsencrypt to {s3z}")
  sh(f'cd {le_dir} && zip -r -q --exclude="*.DS_Store*" "{le_fnz}" .')
  sh(f'aws s3 cp "{le_fnz}" "{s3z}" --sse AES256')

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
  if subdomain == '*' and len(shard) > 0:
    raise ValueError("Wildcard ingress requires an empty shard or the *! no-shard suffix")
  if subdomain == '*' and match.group('subdomain_opt'):
    raise ValueError("Wildcard ingress cannot also request an optional apex")

  fqdns = set([_shard(shard, subdomain, domain)])
  if match.group('subdomain_opt'): fqdns.add(_shard(shard, '', domain))
  if len(fqdns) <= 0: fqdns.add('*')
  return list(fqdns)

# --------------------------------
# LAN-only virtual hosts
# --------------------------------
lan_cidrs = []         # Source networks allowed on private virtual hosts. Empty = feature off.
lan_deny_cidrs = []    # Exceptions carved out of lan_cidrs (e.g., the router's NAT loopback address).
public_fqdns = set()   # FQDNs (after sharding) open to everyone.
public_used = set()    # public_fqdns which matched a virtual host (the rest are config errors).
rbac_per_route = None

# Parse and validate the CIDRs in a config value. A typo must stop startup, not drop a range.
def _parse_cidrs(name):
  nets = []
  for c in sorted(get_uniq_config_values(name)):
    try: net = ipaddress.ip_network(c, strict=True)
    except ValueError as e: raise Exception(f"[lan] invalid {name} entry '{c}': {e}")
    if net.version != 4: raise Exception(f"[lan] {name} entry '{c}' is not IPv4 (unsupported)")
    nets.append(net)
  return nets

# direct_remote_ip is the downstream TCP peer; it ignores X-Forwarded-For (unlike remote_ip).
def _cidr_principals(nets):
  return { 'or_ids': { 'ids': [
    { 'direct_remote_ip': { 'address_prefix': str(n.network_address), 'prefix_len': n.prefixlen } }
    for n in nets
  ] } }

# ALLOW (source in lan_cidrs) AND NOT (source in lan_deny_cidrs)
def _rbac_per_route():
  principal = _cidr_principals(lan_cidrs)
  if len(lan_deny_cidrs) > 0:
    principal = { 'and_ids': { 'ids': [principal, { 'not_id': _cidr_principals(lan_deny_cidrs) }] } }
  return {
    '@type': 'type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBACPerRoute',
    'rbac': { 'rules': { 'action': 'ALLOW', 'policies': {
      'lan-only': { 'permissions': [{ 'any': True }], 'principals': [principal] }
    } } }
  }

def _log_lan(listener_name, virtual_hosts):
  if len(lan_cidrs) <= 0: return
  pub = sorted(set(d for vh in virtual_hosts if not 'typed_per_filter_config' in vh for d in vh['domains']))
  priv = [vh for vh in virtual_hosts if 'typed_per_filter_config' in vh]
  logging.info(f"[lan] {listener_name} public: {', '.join(pub) if pub else '(none)'}  private: {len(priv)} vhosts")

# assumes first fqdn is most unique, and may be used for naming purposes
def _virtual_host(fqdns, routes):
  vh = { "domains": fqdns, "name": "vh-" + fqdns[0], "routes": routes }
  if len(lan_cidrs) > 0:
    pub = [fq for fq in fqdns if fq in public_fqdns]
    if len(pub) > 0 and len(pub) != len(fqdns):
      raise Exception(f"[lan] virtual host {fqdns} is only partly public ({pub}); list all of its names or none")
    public_used.update(pub)
    if len(pub) <= 0:
      vh['typed_per_filter_config'] = { 'envoy.filters.http.rbac': rbac_per_route }
  return vh

def _filter_http_connection_manager(router_name, virtual_hosts = [], base_config = {}):
  def_cfg = {
    "@type": 'type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager',
    'codec_type': 'AUTO',
    'server_name': router_name,
    'stat_prefix': 'ingress_http',
    'add_user_agent': cfg['add_user_agent'],
    'use_remote_address': cfg['use_remote_address'],
    'skip_xff_append': cfg['skip_xff_append'],
    'xff_num_trusted_hops': cfg['xff_num_trusted_hops'],
    'preserve_external_request_id': cfg['preserve_external_request_id'],
    # Envoy 1.12's default notion of "internal" (x-envoy-internal, x-envoy-* header trust); newer
    # versions treat no address as internal unless this is configured.
    'internal_address_config': { 'cidr_ranges': [
      { 'address_prefix': a, 'prefix_len': l } for a, l in
      [('10.0.0.0', 8), ('172.16.0.0', 12), ('192.168.0.0', 16), ('127.0.0.0', 8), ('fc00::', 7), ('::1', 128)]
    ] },
    'access_log': [],
    'http_filters': []
  }
  config = dict(def_cfg)
  config.update(base_config)
  if cfg['auth_port'] > 0:
    config['http_filters'].append({
      'name': 'envoy.filters.http.ext_authz',
      'typed_config': {
        '@type': 'type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz',
        'transport_api_version': 'V3',
        'grpc_service': {
          'envoy_grpc': {
            'cluster_name': 'grpc-ext-authz'
          },
        }
      }
    })
  if len(lan_cidrs) > 0: # No rules = allow all; private virtual hosts override it per-route.
    config['http_filters'].append({
      'name': 'envoy.filters.http.rbac',
      'typed_config': { '@type': 'type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBAC' }
    })
  config['access_log'].append(_file_access_log(router_name))
  config['http_filters'].append({
    'name': 'envoy.filters.http.router',
    'typed_config': { '@type': 'type.googleapis.com/envoy.extensions.filters.http.router.v3.Router' }
  })
  config['route_config'] = { 'virtual_hosts': list(virtual_hosts) }
  if len(cfg['dd_agent_host']) > 0: # The span operation name ("egress") comes from the listener's traffic_direction.
    config['tracing'] = { 'provider': {
      'name': 'envoy.tracers.datadog',
      'typed_config': {
        '@type': 'type.googleapis.com/envoy.config.trace.v3.DatadogConfig',
        'collector_cluster': 'datadog_agent',
        'service_name': 'envoy'
      }
    } }
  return { 'name': 'envoy.filters.network.http_connection_manager', 'typed_config': config }

def _vh_filters(router_name, virtual_hosts = [], config = {}):
  return [{ 'filters': [_filter_http_connection_manager(router_name, virtual_hosts, config)] }]

def _socket_address(address, port):
  return { 'socket_address': { 'address': address, 'port_value': port } }

def _ingress_address(ingress_type):
  return _socket_address(cfg['bind_address'], val2int(cfg[f"{ingress_type}_port"]))

def _admin():
  if len(cfg['admin_access_log']) > 0: log_path = cfg['admin_access_log']
  elif len(cfg['log_path']) > 0: log_path = '%s/envoy_admin.log' % cfg['log_path']
  else: log_path = '/dev/stdout'
  return { 'access_log': [_access_log_file(log_path)], 'address': _ingress_address('admin') }

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
  'grpc': { 'connect_timeout': '25s', 'typed_extension_protocol_options': {
    'envoy.extensions.upstreams.http.v3.HttpProtocolOptions': {
      '@type': 'type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions',
      'explicit_http_config': { 'http2_protocol_options': {} }
    }
  } }
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
  listener = {
    'name': schema,
    'address': _ingress_address(schema),
    'traffic_direction': 'OUTBOUND',
    'filter_chains': filter_chains
  }
  if "USE_PROXY_PROTOCOL" in os.environ:
    if not 'listener_filters' in listener: listener['listener_filters'] = []
    listener['listener_filters'] += [{
      'name': 'envoy.filters.listener.proxy_protocol',
      'typed_config': { '@type': 'type.googleapis.com/envoy.extensions.filters.listener.proxy_protocol.v3.ProxyProtocol' }
    }]
  if schema == 'https':
    if not 'listener_filters' in listener: listener['listener_filters'] = []
    listener['listener_filters'] += [{
      'name': 'envoy.filters.listener.tls_inspector',
      'typed_config': { '@type': 'type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector' }
    }]
  return listener

# --------------------------------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------------------------------
def str2list(string):
  if type(string) is list: return string
  return [x.strip() for x in re.split(r'(\s+)', string) if x.strip()]

def val2int(val):
  if type(val) is int: return val
  if not type(val) is str: raise Exception(f'{val} is not an int or string')
  if len(val) <= 0: return 0
  return int(val)

def val2bool(val):
  if type(val) is bool: return val
  if not type(val) is str: raise Exception(f'{val} is not an bool or string')
  if len(val) <= 0: return 0
  return val.lower() in ("yes", "true", "t", "1")

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
  return [os.path.expandvars(x) for x in ret]

_alive = True
renewal_interval = 86400 * 7 # Attempt certificate renewal weekly...

# Trigger a renewal of certbot certificates. Returns True if renewed.
def _certbot_renew():
  global last_renewal
  logging.info(f'[certbot] renewing certificates...')
  cmd = 'certbot renew --no-random-sleep-on-renew --dns-route53 -q'
  ret = subprocess.run(cmd, shell=True, check=False)
  if ret.returncode != 0:
    logging.error(f'[certbot] failed to renew certificates; err: {ret.stderr}')
    return False

  last_renewal = time.time()

  lf = '/var/log/letsencrypt/letsencrypt.log'
  if not os.path.isfile(lf):
    logging.warning(f'[certbot] renewal succeded, but no log file at {lf}')
    return False

  with open(lf, 'r') as f: logs = f.read().strip()
  if not 'no renewal failures' in logs:
    logging.warning(f'[certbot] certificate renewal may have failed.')
  else:
    logging.info(f'[certbot] renewal completed')

  logging.debug(f'[certbot] renewal log: {logs}')
  return True

# Forked thread which runs indefinitely to renew certs.
def _certbot_thread():
  global new_certs, last_renewal, domain_tls, _alive

  last_renewal = time.time() # If the first renewal fails, retry after renewal_interval.
  _certbot_renew()

  if len(new_certs) > 0:
    logging.info(f'[certbot] new certificates were generated: {new_certs}')
    _backup_certs()

  logging.info(f'[certbot] beginning work loop')
  while _alive:
    elapsed = time.time() - last_renewal
    logging.debug(f'[certbot] elapsed: {elapsed}')
    if elapsed < renewal_interval:
      time.sleep(10)
      continue

    if _certbot_renew():
      _backup_certs()
      # Ugly. Restarts the container. But Envoy doesn't hot reload certificates easily.
      logging.info(f'[certbot] restarting envoy.')
      subprocess.run("pkill envoy", shell=True, check=False, capture_output=False)

  logging.info(f'[certbot] _alive=False, exiting')
  sys.exit(0)

if __name__ == "__main__":
  defcfg = {
    'log_format_switchboard': '[%(asctime)s] [%(process)d] [%(levelname)s] [%(name)s] %(message)s',
    'log_format_access': '',
    'log_format_access_json': '',
    'log_format_envoy': '',
    'log_format_auth': '',
    'log_level': 'INFO',
    'log_path': '',
    'admin_access_log': '',
    'dd_agent_host': '',
    's3_bucket': '',
    'backup': 'letsencrypt',
    'concurrency': 0,
    'timeout': 15.0,
    'bind_address': '0.0.0.0',
    'admin_port': 5000,
    'http_port': 8080,
    'https_port': 8443,
    'use_remote_address': True,
    'add_user_agent': True,
    'skip_xff_append': False,
    'xff_num_trusted_hops': 0,
    'preserve_external_request_id': True,
    'auth_port': 0,
    'default_route': '',
    'shard': '',
    'email': '',
    'stats_type': '',
    'lan_cidrs': '',
    'lan_deny_cidrs': '',
    'validate_only': False,
  }
  cfg = dict(defcfg)
  if os.path.isfile('/etc/switchboard/config.yml'):
    with open('/etc/switchboard/config.yml', 'r') as stream:
      cfg.update(yaml.safe_load(stream))
  for var_name in cfg:
    cfg[var_name] = os.getenv(var_name.upper(), cfg[var_name])
    if type(defcfg[var_name]) is int: cfg[var_name] = val2int(cfg[var_name])
    if type(defcfg[var_name]) is bool: cfg[var_name] = val2bool(cfg[var_name])

  envoy_flags = ['-c', '/etc/envoy/envoy.yaml']
  if len(cfg['log_path']) > 0:
    fn = '%s/switchboard.log' % cfg['log_path']
    envoy_flags += ['--log-path', '%s/envoy.log' % cfg['log_path']]
    logging.basicConfig(filename=fn, format=cfg['log_format_switchboard'], level=cfg['log_level'])
  else:
    envoy_flags += ['--log-path', '/dev/stdout']
    logging.basicConfig(format=cfg['log_format_switchboard'], level=cfg['log_level'])

  # [LAN] Setting lan_cidrs makes every virtual host LAN-only unless all its names are `public`.
  lan_cidrs = _parse_cidrs('lan_cidrs')
  lan_deny_cidrs = _parse_cidrs('lan_deny_cidrs')
  public_fqdns = set(get_uniq_config_values('public'))
  if len(lan_cidrs) > 0:
    rbac_per_route = _rbac_per_route()
    logging.info(f"[lan] allow: {', '.join(map(str, lan_cidrs))}  deny: {', '.join(map(str, lan_deny_cidrs)) or '(none)'}")
  elif len(lan_deny_cidrs) > 0 or len(public_fqdns) > 0:
    logging.warning('[lan] lan_deny_cidrs / public are ignored because lan_cidrs is empty (all hosts are public)')

  ingress_values = get_uniq_config_values('ingress')
  logging.debug(f"Ingress Regex: {re_ingress}")
  logging.debug(f"Ingress Config: {ingress_values}")

  destinations = get_uniq_config_values('egress')
  logging.debug(f"Egress Regex: {re_egress}")
  logging.debug(f"Egress Config: {destinations}")

  # [Egress] Build Routes
  dest_clusters = {}
  dest_schemas = defaultdict(set)

  # [Authorization] Start Go server?
  if cfg['auth_port'] > 0:
    logging.info('starting ext-authz on port #%s' % cfg['auth_port'])
    destinations.append('ext-authz:grpc@localhost:%s' % cfg['auth_port'])
    if not cfg['validate_only']:
      spawn('/usr/local/bin/ext-authz %s %s %s' % (
        cfg['auth_port'], cfg['log_level'], cfg['log_format_auth']))

  if len(cfg['dd_agent_host']) > 0:
    dest_clusters['datadog_agent'] = {
      'name': 'datadog_agent',
      'connect_timeout': '1s',
      'type': 'STRICT_DNS',
      'lb_policy': 'ROUND_ROBIN',
      'load_assignment': { 'cluster_name': 'datadog_agent', 'endpoints': _endpoints(cfg['dd_agent_host'], 8126) }
    }

  for dest_str in destinations:
    log = logging.getLogger(f"<egress>{dest_str}")
    dest_match = re_eg_matcher.match(dest_str)
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
  secure_filter_chains = {}
  secure_domain_routes = defaultdict(list)
  unsecure_domain_routes = defaultdict(list)
  unsecure_web_sockets = False

  for ingress_str in ingress_values: # Iterate virtual hosts
    log = logging.getLogger(f"<ingress>{ingress_str}")
    ingress_match = re_in_matcher.match(ingress_str)
    if not ingress_match:
      raise Exception(f"No regex match for ingress config str: {ingress_str}")

    ingress_schema_str = ingress_match.group('schema')
    domain = ingress_match.group('domain')
    fqdns = _get_fqdns(ingress_match)
    splitter = '|'
    fqdns_str = splitter.join(fqdns)
    dest_name = ingress_match.group('dest')
    path = ingress_match.group('path') if len(ingress_match.group('path')) > 0 else '/'
    filter_config = {}
    route_options = {}
    if ingress_match.group('strip_path'): route_options['prefix_rewrite'] = '/'
    if ingress_schema_str == 'wss': # Allow for simple upgrading of connection when HTTPS
      filter_config['upgrade_configs'] = [{ 'upgrade_type': 'websocket' }]
      ingress_schema_str = 'https'
    if ingress_match.group('schema_req'): # Configure a http -> https redirect
      log.info(f"redirect to secure for {ingress_schema_str}{fqdns}")
      routes = [_match_redirect({ 'https_redirect': True }, 'http', path)]
      for fqdn in fqdns:
        unsecure_domain_routes[fqdn] += routes
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
      routes = _match_routes_egress(listener_schema, dest_name, path, route_options)

      log.debug(f'listener {listener_schema} with routes {routes}')
      if listener_schema == 'https':
        sfc = secure_filter_chains[domain] if domain in secure_filter_chains else {
          'filter_chain_match': { "server_names": [] },
          'filters': [_filter_http_connection_manager('-'.join(['https', domain]))],
          'transport_socket': {
            'name': 'envoy.transport_sockets.tls',
            'typed_config': {
              "@type": 'type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext',
              'common_tls_context': {
                'tls_certificates': [c for c in [_certificate(domain)] if c],
                'alpn_protocols': [ "h2", "http/1.1" ],
              }
            }
          }
        }
        # Add all the domains to the server names.
        fqdns = fqdns_str.split(splitter)
        for fq in fqdns:
          if not fq in sfc['filter_chain_match']['server_names']:
            sfc['filter_chain_match']['server_names'].append(fq)

        # Update the filter with a virtual host and any necessary config tweaks.
        vh = _virtual_host(fqdns, routes)
        sfc['filters'][0]['typed_config']['route_config']['virtual_hosts'].append(vh)
        sfc['filters'][0]['typed_config'].update(filter_config)

        secure_filter_chains[domain] = sfc
      elif listener_schema == 'http':
        unsecure_domain_routes[fqdns_str] += routes
      elif listener_schema == 'ws':
        unsecure_web_sockets = True
        unsecure_domain_routes[fqdns_str] += routes
      else:
        raise Exception(f"do not know how to configure {listener_schema} routes")
  # [Ingress] End

  if len(cfg['default_route']) > 0:
    logging.info("Default HTTP Route: " + cfg['default_route'])
    routes = _match_routes_egress('http', cfg['default_route'])
    unsecure_domain_routes['*'] += routes

  logging.debug("unsecure domain routes: " + json.dumps(unsecure_domain_routes, indent=2))
  logging.debug("secure filter chains: " + json.dumps(secure_filter_chains , indent=2))
  logging.debug("secure domain routes: " + json.dumps(secure_domain_routes, indent=2))

  listeners = []
  if len(secure_filter_chains) > 0:
    matches = []
    for domain in secure_filter_chains:
      matches.append(secure_filter_chains[domain])
    # An unmatched SNI has no certificate to present, so there is no fallback chain: envoy closes
    # the connection. (Older versions emitted a malformed plaintext `*` chain that had the same effect.)
    listeners.append(_listener('https', matches))
    _log_lan('https', [vh for fc in matches for vh in fc['filters'][0]['typed_config']['route_config']['virtual_hosts']])
    logging.info("[bind] https://%s:%s" % (cfg['bind_address'], cfg['https_port']))

  if len(unsecure_domain_routes) > 0:
    schema = 'http'
    vhs = [_virtual_host(fqdns_str.split(splitter), unsecure_domain_routes[fqdns_str]) for fqdns_str in unsecure_domain_routes]
    filter_config = {}
    if unsecure_web_sockets:
      filter_config['upgrade_configs'] = [{ 'upgrade_type': 'websocket' }]
    listeners.append(_listener(schema, _vh_filters(schema, vhs, filter_config)))
    _log_lan(schema, vhs)
    logging.info("[bind] %s://%s:%s" % (schema, cfg['bind_address'], cfg['http_port']))

  if len(listeners) <= 0: raise Exception("No listeners created.")
  if len(lan_cidrs) > 0 and len(public_fqdns - public_used) > 0:
    raise Exception(f"[lan] public names match no virtual host: {sorted(public_fqdns - public_used)}")

  resources = { 'listeners': listeners, 'clusters': list(dest_clusters.values()) }
  data = { "static_resources": resources, 'stats_sinks': [] }
  if cfg['admin_port'] > 0: data['admin'] = _admin()
  if len(cfg['stats_type']) > 0:
    if cfg['stats_type'] == 'statsd':
      if not cfg['validate_only']: spawn('/bin/statsd_exporter')
      data['stats_sinks'].append({
        'name': 'envoy.stat_sinks.statsd',
        'typed_config': {
          '@type': 'type.googleapis.com/envoy.config.metrics.v3.StatsdSink',
          'address': _socket_address("127.0.0.1", 9125)
        }
      })
    elif cfg['stats_type'] == 'dog_statsd':
      data['stats_sinks'].append({
        'name': 'envoy.stat_sinks.dog_statsd',
        'typed_config': {
          '@type': 'type.googleapis.com/envoy.config.metrics.v3.DogStatsdSink',
          'address': _socket_address(cfg['dd_agent_host'], 8125)
        }
      })
    else:
      raise Exception("Unknown stats_type: " + cfg['stats_type'])

  sh('mkdir -p /etc/envoy')
  with open('/etc/envoy/envoy.yaml', 'w') as outfile:
    yaml.dump(data, outfile, default_flow_style=False)

  if cfg['validate_only']: # Check the generated config without certbot, S3, or serving traffic.
    os.environ[empty_env_var] = ''
    cmd = '/usr/local/bin/envoy --mode validate --disable-hot-restart -c /etc/envoy/envoy.yaml'
    logging.info(f'[validate] {cmd}')
    res = subprocess.run(cmd, shell=True, check=False, capture_output=False)
    logging.info(f'[validate] envoy exited with return code: {res.returncode}')
    exit(res.returncode)

  if len(domain_tls) > 0:
    # Cleanup unused certificates:
    if os.path.isdir(f'{le_dir}/live'):
      for dname in os.listdir(f'{le_dir}/live'): # Enumerate the sites in the live directory
        if dname in domain_tls: continue

        live_dir = os.path.join(f'{le_dir}/live', dname)
        if not os.path.isdir(live_dir): continue

        logging.info(f'[certbot] removing unused certificates for {dname}...')
        shutil.rmtree(live_dir)

        cf = f'{le_dir}/renewal/{dname}.conf'
        if os.path.isfile(cf): os.remove(cf)

    logging.info('[certbot] forking')
    if os.fork() == 0:
      logging.info('[certbot] forked')
      _certbot_thread()

  if cfg['concurrency'] > 0:
    envoy_flags += ['--concurrency', str(cfg['concurrency'])]
  if cfg['log_level'].upper() != 'INFO': envoy_flags += ['-l', cfg['log_level'].lower()]
  if len(cfg['log_format_envoy']) > 0:
    envoy_flags += ['--log-format', "\"" + cfg['log_format_envoy'] + "\""]

  os.environ[empty_env_var] = ''
  cmd = f'/usr/local/bin/envoy ' + ' '.join(envoy_flags)
  logging.debug(f'Starting envoy with command: {cmd}')
  res = subprocess.run(cmd, shell=True, check=False, capture_output=False)
  logging.info(f'Exiting with return code: {res.returncode}')
  _alive = False;
  exit(res.returncode)
