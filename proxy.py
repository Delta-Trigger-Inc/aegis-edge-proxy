"""Explicit-config launcher for the native proxy reference preview."""
import argparse,json,os,sys,ipaddress
from pathlib import Path
from types import SimpleNamespace
from proxy_runtime import NativeProxy,_native_open

def load(path):
    value=json.loads(Path(path).read_text())
    required={'listen_host','listen_port','edge_id','proxy_id','endpoint_id','configuration_version','source_ip','allowed_destination_cidr','maximum_connections','connect_timeout','header_timeout','ca_file','server_cert','server_key','proxy_signing_key','edge_signing_public_key','health_file'}
    if set(value)!=required:raise ValueError('Unexpected or missing configuration fields')
    for key in ['edge_id','proxy_id','endpoint_id','configuration_version']:
        if not isinstance(value[key],str) or not 1<=len(value[key])<=160:raise ValueError('Invalid identity field')
    for key in ['source_ip','listen_host']:ipaddress.IPv4Address(value[key])
    if type(value['listen_port']) is not int or not 1024<=value['listen_port']<=65535:raise ValueError('Unprivileged listener port required')
    if type(value['maximum_connections']) is not int or not 1<=value['maximum_connections']<=32:raise ValueError('Preview connection limit must be 1..32')
    if not value['allowed_destination_cidr']:raise ValueError('Explicit test destination CIDRs required')
    for cidr in value['allowed_destination_cidr']:
        net=ipaddress.IPv4Network(cidr)
        if net.prefixlen<24:raise ValueError('Preview requires narrow approved test CIDRs (/24 or narrower)')
    for key in ['connect_timeout','header_timeout']:
        if type(value[key]) not in (int,float) or not 0<value[key]<=30:raise ValueError('Invalid timeout')
    for key in ['ca_file','server_cert','server_key','proxy_signing_key','edge_signing_public_key']:
        if not Path(value[key]).is_absolute() or not Path(value[key]).is_file():raise ValueError('Credential file missing: '+key)
    return SimpleNamespace(**value)

def main():
    parser=argparse.ArgumentParser(description='AEGIS native proxy — controlled-test preview')
    parser.add_argument('--config',required=True)
    parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    config=load(args.config)
    if args.check:
        print('Configuration and credential paths valid; sockets not opened.');return
    if os.geteuid()==0:raise SystemExit('Run the proxy as an unprivileged user')
    NativeProxy(config).serve()
if __name__=='__main__':main()
