#!/usr/bin/python3.7
import yaml, json, configparser, os, subprocess, re, logging, time, shutil
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

re_certbot_filename = _re_param("name", "\w+")
re_certbot_version = _re_param("version", "\d+")
re_certbot_pem_matcher = re.compile(f"^{re_certbot_filename}{re_certbot_version}\.pem$")

# Ingress regex
re_in_schema = "".join([
  _re_param("schema", "\w+"),
  _re_param("schema_opt", "\??"), # If ends with ?, listen on both secure and insecure
  _re_param("schema_req", "\!?") # If ends with !, enforce this schema (redirect http to https)
])
re_in_subdomain = "".join([
  _re_param("subdomain", "[a-z0-9-]*"),
  _re_param("subdomain_opt", "\??"), # If ends with ?, also listen on no-subdomain version
  _re_param("subdomain_no_shard", "\!?"), # If ends with !, consider final: do not apply sharding.
])
re_in_domain = _re_param("domain", "[\.a-z0-9-]+")
re_in_path = "".join([
  _re_param("path", "[\.\/A-Za-z0-9-]*"),
  _re_param("strip_path", "\!?") # If ends with !, strip the path prefix
])
re_in_dest = _re_param("dest", "[\.a-z0-9-]+")
re_ingress = f"^{re_in_schema}://{re_in_subdomain}:{re_in_domain}{re_in_path}@{re_in_dest}$"
re_in_matcher = re.compile(re_ingress)

# Egress Regex
re_eg_dest = _re_param("dest", "[a-z0-9-]+")
re_eg_schema = _re_param("schema", "\w+")
re_eg_domain = _re_param("domain", "[\.a-z0-9-]+")
re_eg_port = _re_param("port", "[0-9]+")
re_egress = f"^{re_eg_dest}:{re_eg_schema}@{re_eg_domain}:{re_eg_port}$"
re_eg_matcher = re.compile(re_egress)

# --------------------------------------------------------------------------------------------------

def _file_access_log(router_name):
  ret = {
    "name": "envoy.file_access_log", # TODO: envoy.access_loggers.file
    'filter': { 'not_health_check_filter': {} },
    "typed_config": {
      '@type': 'type.googleapis.com/envoy.config.accesslog.v2.FileAccessLog'
    }
  }
  if len(cfg['log_path']) > 0:
    ret['typed_config']['path'] = '%s/%s.log' % (cfg['log_path'], router_name)
  else: ret['typed_config']['path'] = '/dev/stdout'

  if len(cfg['log_format_access']) > 0:
    ret['typed_config']['format'] = cfg['log_format_access'].replace('%ROUTER%', router_name)
  elif len(cfg['log_format_access_json']) > 0:
    ret['typed_config']['json_format'] = json.loads(
      cfg['log_format_access_json'].replace('%ROUTER%', router_name))

  return ret

def sh(cmd):
  ret = subprocess.run(cmd, shell=True, check=False, capture_output=True, text=True)
  stdout = ret.stdout.strip()
  stderr = ret.stderr.strip()
  if ret.returncode != 0:
    raise Exception(f'Failed to run {cmd} because:\nstdout: "{stdout}"\nstderr: "{stderr}"')
  return stdout

# Route traffic (within a virtual host) to a specific cluster.
def _match_route(base, dest_schema, prefix = '/', match_options = {}):
  ret = dict(base)
  ret['match'] = dict(match_options)
  if dest_schema == 'grpc':
    ret['match']['headers'] = { "name": "content-type", "exact_match": "application/grpc" }
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
    routes.append(_match_route({ 'route': route }, dest_schema, path_prefix))
  return routes

def _certificate(domain):
  global certbot_renewal, new_certs, domain_tls

  if domain in domain_tls: # Use cached version.
    logging.info(f'certificate already generated for {domain}')
    return domain_tls[domain]

  s3z = f"s3://{cfg['s3_bucket']}/letsencrypt.zip" if len(cfg['s3_bucket']) > 0 else None
  if not os.path.isdir(le_dir):
    logging.warning(f"skipping _certificate for {domain}")
    return {}
  if s3z and not os.path.isdir(f'{le_dir}/renewal'):
    logging.info(f'restoring certificates from {s3z}')
    try:
      sh(f'aws s3 cp "{s3z}" "{le_fnz}"')
      sh(f'unzip -q -o "{le_fnz}" -d "{le_dir}"')
    except Exception as e:
      logging.error(f'{e}')
    if os.path.isdir(f'{le_dir}/live'):
      for dname in os.listdir(f'{le_dir}/live'): # Enumerate the sites in the live directory
        live_dir = os.path.join(f'{le_dir}/live', dname)
        archive_dir = f'{le_dir}/archive/{dname}'
        if not os.path.isdir(live_dir): continue
        logging.info(f'linking certificates for {dname}')
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
          logging.debug(f'symlinking {src} to {dst}')
          sh(f'rm -rf {dst} && ln -s "{src}" "{dst}"')

  email = cfg['email']
  if len(email) <= 0:
    logging.warning(f"cannot generate a certificate for {domain} because no email provided")
    return {}

  fn_renew = f"{le_dir}/renewal/{domain}.conf"
  cb_flags = '' # --post-hook "sudo service nginx reload"
  if not os.path.isfile(fn_renew):
    new_certs.append(domain)
    logging.info(f'requesting certificate for {domain}')
    sh(
      f'certbot certonly {cb_flags} -d \"*.{domain}\" -d {domain} -m {email} ' +
      '--server https://acme-v02.api.letsencrypt.org/directory --agree-tos --non-interactive'
    )

  if not os.path.isdir('/etc/letsencrypt/live/' + domain):
    logging.error("Failed to get a certificate for " + domain)
    # raise Exception("Failed to get a certificate for " + domain)
  # if s3z:
    # Back up with every cert creation, so that intermediate progress is saved
    # In the case there are lots of certs, this can be a useful trait if containers
    # are killed by some health check daemon.
    # with open('/var/log/letsencrypt/letsencrypt.log', 'r') as lf:
      # log = lf.read()
      # if "-BEGIN CERTIFICATE-" in log:
  if os.path.isfile('/var/log/letsencrypt/letsencrypt.log'):
      os.rename('/var/log/letsencrypt/letsencrypt.log', '/var/log/letsencrypt/%s.log' % domain)
  domain_tls[domain] = {
    "certificate_chain": { "filename": "/etc/letsencrypt/live/%s/fullchain.pem" % domain },
    "private_key": { "filename": "/etc/letsencrypt/live/%s/privkey.pem" % domain }
  }
  return domain_tls[domain]

# Back up the certificates to s3
def _backup_certs():
  s3z = f"s3://{cfg['s3_bucket']}/letsencrypt.zip" if len(cfg['s3_bucket']) > 0 else None

  logging.info(f"backing up letsencrypt to {s3z}")
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

  fqdns = set([_shard(shard, subdomain, domain)])
  if match.group('subdomain_opt'): fqdns.add(_shard(shard, '', domain))
  if len(fqdns) <= 0: fqdns.add('*')
  return list(fqdns)

# assumes first fqdn is most unique, and may be used for naming purposes
def _virtual_host(fqdns, routes):
  return { "domains": fqdns, "name": "vh-" + fqdns[0], "routes": routes }

def _filter_http_connection_manager(router_name, virtual_hosts = [], base_config = {}):
  def_cfg = {
    "@type": 'type.googleapis.com/envoy.config.filter.network.http_connection_manager.v2.HttpConnectionManager',
    'codec_type': 'AUTO',
    'server_name': router_name,
    'stat_prefix': 'ingress_http',
    'add_user_agent': cfg['add_user_agent'],
    'use_remote_address': cfg['use_remote_address'],
    'skip_xff_append': cfg['skip_xff_append'],
    'xff_num_trusted_hops': cfg['xff_num_trusted_hops'],
    'preserve_external_request_id': cfg['preserve_external_request_id'],
    'access_log': [],
    'http_filters': []
  }
  config = dict(def_cfg)
  config.update(base_config)
  if cfg['auth_port'] > 0:
    config['http_filters'].append({
      'name': 'envoy.ext_authz',
      'config': {
        'grpc_service': {
          'envoy_grpc': {
            'cluster_name': 'grpc-ext-authz'
          },
        }
      }
    })
  config['access_log'].append(_file_access_log(router_name))
  config['http_filters'].append({ 'name': 'envoy.router', 'typed_config': {} }) # envoy.filters.http.router
  config['route_config'] = { 'virtual_hosts': list(virtual_hosts) }
  if len(cfg['dd_agent_host']) > 0:
    config['tracing'] = { 'operation_name': 'egress' }
  # 1.14.0 TODO: envoy.filters.network.http_connection_manager
  return { 'name': 'envoy.http_connection_manager', 'typed_config': config }

def _vh_filters(router_name, virtual_hosts = [], config = {}):
  return [{ 'filters': _filter_http_connection_manager(router_name, virtual_hosts, config) }]

def _socket_address(address, port):
  return { 'socket_address': { 'address': address, 'port_value': port } }

def _ingress_address(ingress_type):
  return _socket_address(cfg['bind_address'], val2int(cfg[f"{ingress_type}_port"]))

def _admin():
  if len(cfg['log_path']) > 0: log_path = '%s/envoy_admin.log' % cfg['log_path']
  else: log_path = '/dev/stdout'
  return { 'access_log_path': log_path, 'address': _ingress_address('admin') }

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
  listener = {
    'name': schema,
    'address': _ingress_address(schema),
    'traffic_direction': 'INBOUND',
    'filter_chains': filter_chains
  }
  if "USE_PROXY_PROTOCOL" in os.environ:
    if not 'listener_filters' in listener: listener['listener_filters'] = []
    listener['listener_filters'] += [{'name': 'envoy.listener.proxy_protocol'}]
  if schema == 'https':
    if not 'listener_filters' in listener: listener['listener_filters'] = []
    listener['listener_filters'] += [{'name': 'envoy.listener.tls_inspector', 'typed_config': {}}]
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
renewal_interval = 86400 # Attempt certificate renewal daily...

# Trigger a renewal of certbot certificates. Returns True if renewed.
def _certbot_renew():
  global last_renewal
  logging.info(f'Renewing certificates...')
  cmd = 'certbot renew --no-random-sleep-on-renew --dns-route53 -q'
  ret = subprocess.run(cmd, shell=True, check=False)
  if ret.returncode != 0:
    logging.error(f'Failed to renew certificates; err: {ret.stderr}')
    return False

  last_renewal = time.time()

  lf = '/var/log/letsencrypt/letsencrypt.log'
  if not os.path.isfile(lf):
    logging.warning(f'Renewal succeded, but no log file at {lf}')
    return False

  with open(lf, 'r') as f: logs = f.read().strip()
  if 'Your certificate and chain have been saved' in logs:
    logging.info(f'Certificate change detected.')
    return True

  logging.info('No certificate change detected.')
  return False

# Forked thread which runs indefinitely to renew certs.
def _certbot_thread():
  global new_certs, last_renewal, domain_tls, _alive

  _certbot_renew()

  if len(new_certs) > 0:
    logging.info(f'New certificates were generated: {new_certs}')
    _backup_certs()

  while _alive:
    elapsed = time.time() - last_renewal
    if elapsed < renewal_interval:
      time.sleep(10)
      continue

    if _certbot_renew():
      _backup_certs()

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
    'dd_agent_host': '',
    's3_bucket': '',
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

  ingress_values = get_uniq_config_values('ingress')
  logging.debug(f"Ingress Regex: {re_ingress}")
  logging.debug(f"Ingress Config: {ingress_values}")

  destinations = get_uniq_config_values('egress')
  logging.debug(f"Egress Regex: {re_egress}")
  logging.debug(f"Egress Config: {destinations}")

  # [Egress] Build Routes
  dest_clusters = {}
  dest_schemas = defaultdict(set)
  tracing = {}

  # [Authorization] Start Go server?
  if cfg['auth_port'] > 0:
    logging.info('starting ext-authz on port #%s' % cfg['auth_port'])
    destinations.append('ext-authz:grpc@localhost:%s' % cfg['auth_port'])
    sh('/usr/local/bin/ext-authz %s %s %s &' % (
      cfg['auth_port'], cfg['log_level'], cfg['log_format_auth']))

  if len(cfg['dd_agent_host']) > 0:
    dest_clusters['datadog_agent'] = {
      'name': 'datadog_agent',
      'connect_timeout': '1s',
      'type': 'strict_dns',
      'lb_policy': 'ROUND_ROBIN',
      'hosts': [{
        'socket_address': {
          'address': cfg['dd_agent_host'],
          'port_value': 8126
        }
      }]
    }
    tracing['http'] = {
      'name': 'envoy.tracers.datadog',
      'config': {
        'collector_cluster': 'datadog_agent',
        'service_name': 'envoy'
      }
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
              "@type": 'type.googleapis.com/envoy.api.v2.auth.DownstreamTlsContext',
              'common_tls_context': {
                'tls_certificates':  _certificate(domain)
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
    # Redirect unmatched HTTPS back to HTTP...
    route_http = _match_redirect({ 'scheme_redirect': 'http' }, 'https')
    matches.append(_vh_filters('https', [_virtual_host(["*"], route_http)]))
    listeners.append(_listener('https', matches))
    logging.info("[bind] https://%s:%s" % (cfg['bind_address'], cfg['https_port']))

  if len(unsecure_domain_routes) > 0:
    schema = 'http'
    vhs = [_virtual_host(fqdns_str.split(splitter), unsecure_domain_routes[fqdns_str]) for fqdns_str in unsecure_domain_routes]
    filter_config = {}
    if unsecure_web_sockets:
      filter_config['upgrade_configs'] = [{ 'upgrade_type': 'websocket' }]
    listeners.append(_listener(schema, _vh_filters(schema, vhs, filter_config)))
    logging.info("[bind] %s://%s:%s" % (schema, cfg['bind_address'], cfg['http_port']))

  if len(listeners) <= 0: raise Exception("No listeners created.")

  resources = { 'listeners': listeners, 'clusters': list(dest_clusters.values()) }
  data = { "static_resources": resources, 'stats_sinks': [], 'tracing': tracing }
  if cfg['admin_port'] > 0: data['admin'] = _admin()
  if len(cfg['stats_type']) > 0:
    if cfg['stats_type'] == 'statsd':
      sh('/bin/statsd_exporter &')
      data['stats_sinks'].append({
        'name': 'envoy.statsd',
        'config': {
          'address': _socket_address("127.0.0.1", 9125)
        }
      })
    else:
      raise Exception("Unknown stats_type: " + cfg['stats_type'])

  sh('mkdir -p /etc/envoy')
  with open('/etc/envoy/envoy.yaml', 'w') as outfile:
    yaml.dump(data, outfile, default_flow_style=False)

  if len(domain_tls) > 0:
    # Cleanup unused certificates:
    if os.path.isdir(f'{le_dir}/live'):
      for dname in os.listdir(f'{le_dir}/live'): # Enumerate the sites in the live directory
        if dname in domain_tls: continue

        live_dir = os.path.join(f'{le_dir}/live', dname)
        if not os.path.isdir(live_dir): continue

        logging.info(f'removing unused certificates for {dname}...')
        shutil.rmtree(live_dir)

        cf = f'{le_dir}/renewal/{dname}.conf'
        if os.path.isfile(cf): os.remove(cf)

    if os.fork() == 0: _certbot_thread()

  if cfg['log_level'].upper() != 'INFO': envoy_flags += ['-l', cfg['log_level'].lower()]
  if len(cfg['log_format_envoy']) > 0:
    envoy_flags += ['--log-format', "\"" + cfg['log_format_envoy'] + "\""]

  cmd = f'/usr/local/bin/envoy ' + ' '.join(envoy_flags)
  logging.debug(f'Starting envoy with command: {cmd}')
  res = subprocess.run(cmd, shell=True, check=False, capture_output=False)
  logging.info(f'Exiting with return code: {res.returncode}')
  _alive = False;
  exit(res.returncode)
