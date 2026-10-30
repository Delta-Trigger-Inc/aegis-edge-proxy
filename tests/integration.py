"""Run inside the Linux preview image as UID 10001; no external network needed."""
import json,os,socket,subprocess,sys,tempfile,threading,time
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0,'/app')
from proxy_runtime import _native_open
root=Path(tempfile.mkdtemp(prefix='proxy-test-'));bundle=root/'pair'
subprocess.run([sys.executable,'/app/create_pair.py','--edge-id','test-edge','--proxy-id','test-proxy','--endpoint-id','test-endpoint','--source-ip','127.0.0.1','--server-name','proxy.test','--allowed-destination-cidr','127.0.0.1/32','--output',str(bundle)],check=True)
cfg=json.loads((bundle/'proxy/config.json').read_text())
for name in ['ca_file','server_cert','server_key','proxy_signing_key','edge_signing_public_key']:cfg[name]=str(bundle/'proxy'/Path(cfg[name]).name)
cfg['health_file']=str(root/'health.json');config=root/'config.json';config.write_text(json.dumps(cfg))
subprocess.run([sys.executable,'/app/proxy.py','--config',str(config),'--check'],check=True)
receiver=socket.socket();receiver.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);receiver.bind(('127.0.0.1',25));receiver.listen();receiver.settimeout(10);peers=[]
def receive():
    c,peer=receiver.accept();peers.append(peer[0]);c.settimeout(5)
    with c:
        c.sendall(b'220 controlled-test\r\n');data=c.recv(32);assert data==b'preview-payload';c.sendall(data)
thread=threading.Thread(target=receive);thread.start()
log=(root/'proxy.log').open('w');process=subprocess.Popen([sys.executable,'/app/proxy.py','--config',str(config)],stdout=log,stderr=log)
try:
    for _ in range(100):
        if (root/'health.json').exists():break
        if process.poll() is not None:raise AssertionError('proxy exited before ready')
        time.sleep(.05)
    assert (root/'health.json').exists()
    edge=bundle/'edge'
    args=SimpleNamespace(proxy_host='127.0.0.1',proxy_port=5443,edge_id='test-edge',proxy_id='test-proxy',endpoint_id='test-endpoint',configuration_version='1',connect_timeout=3,header_timeout=3,ca_file=str(edge/'ca.pem'),client_cert=str(edge/'client.pem'),client_key=str(edge/'client.key'),edge_signing_key=str(edge/'edge-signing.key'),proxy_signing_public_key=str(edge/'proxy-signing-public.pem'),proxy_server_name='proxy.test',no_client_cert=False,channel_binding_mismatch=False)
    c,r=_native_open(args,destination='127.0.0.1',destination_port=25,request_id='integration-request-001');assert r['status']=='accepted';assert c.version()=='TLSv1.3'
    assert c.recv(100)==b'220 controlled-test\r\n';c.sendall(b'preview-payload');assert c.recv(100)==b'preview-payload';c.close();thread.join(5);assert not thread.is_alive() and peers==['127.0.0.1']
    c,r=_native_open(args,destination='127.0.0.1',destination_port=25,request_id='integration-request-001');c.close();assert r['reason']=='request_replayed'
    c,r=_native_open(args,destination='127.0.0.2',destination_port=25);c.close();assert r['reason']=='destination_not_allowed'
    args.no_client_cert=True
    try:
        c,r=_native_open(args,destination='127.0.0.1',destination_port=25);c.close();raise AssertionError('missing client certificate accepted')
    except (OSError,ConnectionError):pass
    print('PASS: real TLS 1.3, mutual auth, signed responses, source binding, bidirectional bytes, replay rejection, destination rejection, missing-client-certificate rejection')
finally:
    process.terminate();process.wait(timeout=10);receiver.close();log.close()
