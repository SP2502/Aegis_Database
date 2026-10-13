#!/usr/bin/env python3
"""Offline shell publication tests. No real GitHub operations are performed."""
import base64,json,os,pathlib,shutil,subprocess,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
FAKE_GH=r'''#!/usr/bin/env python3
import json,os,pathlib,shutil,sys
args=sys.argv[1:];state_path=pathlib.Path(os.environ['FAKE_GH_STATE']);st=json.loads(state_path.read_text());st['calls'].append(args)
scenario=os.environ.get('FAKE_GH_SCENARIO','success')
def save():state_path.write_text(json.dumps(st))
def err(status,message):
 print(json.dumps({'message':message}));print(f'gh: {message} (HTTP {status})',file=sys.stderr);save();sys.exit(1)
if args[0]=='api':
 endpoint=args[1]
 if endpoint.endswith('/immutable-releases'):print('true')
 elif endpoint.endswith('/releases/latest'):
  if scenario=='previous_error':err(403,'Forbidden')
  if scenario=='bootstrap':err(404,'Not Found')
  print(json.dumps({'tag_name':'rules-20261012060000'}))
 elif '/releases?' in endpoint:
  if scenario=='api_error':err(503,'Unavailable')
  print('rules-20261012060000' if scenario=='existing' else '')
 elif '/git/ref/tags/' in endpoint:
  if scenario=='existing_tag':print(json.dumps({'ref':'existing'}))
  else:err(404,'Not Found')
 else:err(404,'Unknown fake endpoint')
elif args[:2]==['release','create']:
 assert '--draft' in args
 st['draft']=True
elif args[:2]==['release','upload']:
 assert st.get('draft')
 assets=pathlib.Path(os.environ['FAKE_ASSETS']);assets.mkdir(exist_ok=True)
 for v in args[3:]:
  p=pathlib.Path(v)
  if p.is_file():shutil.copy2(p,assets/p.name)
 st['uploaded']=True
elif args[:2]==['release','download']:
 dest=pathlib.Path(args[args.index('--dir')+1]);dest.mkdir(exist_ok=True)
 patterns=[args[i+1] for i,v in enumerate(args) if v=='--pattern']
 assets=pathlib.Path(os.environ['FAKE_ASSETS'])
 for name in patterns:
  shutil.copy2(assets/name,dest/name)
  if scenario=='corrupt_download' and name=='aegis-rules.bin.gz':
   with (dest/name).open('ab') as f:f.write(b'corrupt')
 st['downloaded']=True
elif args[:2]==['release','edit']:
 assert st.get('draft') and st.get('uploaded') and st.get('downloaded')
 assert '--draft=false' in args and '--latest' in args
 st['published']=True
else:err(500,'Unsupported fake invocation')
save()
'''
class PublicationTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tmp=tempfile.TemporaryDirectory();cls.base=pathlib.Path(cls.tmp.name)
  cls.keys=cls.base/'keys'
  subprocess.run([str(ROOT/'bin/aegis-keygen'),'-out',str(cls.keys)],check=True,capture_output=True)
  cls.release=cls.base/'fixture'
  subprocess.run([str(ROOT/'bin/aegis-builder'),'-sources',str(ROOT/'fixtures/sources.json'),'-fixtures',str(ROOT/'fixtures'),'-repository','fixture/AEGIS-Intelligence','-key-file',str(cls.keys/'signing.seed'),'-out',str(cls.release),'-created-at','2026-10-12T06:00:00Z'],check=True,capture_output=True)
 @classmethod
 def tearDownClass(cls):cls.tmp.cleanup()
 def setup_run(self,scenario='success'):
  work=pathlib.Path(tempfile.mkdtemp(dir=self.base));(work/'bin').mkdir();(work/'out').mkdir();(work/'docs').mkdir()
  shutil.copy2(ROOT/'bin/aegis-verify',work/'bin/aegis-verify');shutil.copytree(self.release,work/'out/release')
  for name in ['BLOCKLISTPROJECT-LICENSE.txt','BLOCKLISTPROJECT-NOTICE.txt']:shutil.copy2(ROOT/'docs'/name,work/'docs'/name)
  fake=work/'bin/gh';fake.write_text(FAKE_GH);fake.chmod(0o700)
  state=work/'state.json';state.write_text(json.dumps({'calls':[]}));assets=work/'fake-assets';shutil.copytree(self.release,assets)
  output=work/'output.txt';output.touch()
  env=os.environ.copy();env.update(PATH=str(work/'bin')+os.pathsep+env['PATH'],GH_TOKEN='test-only-token',GITHUB_REPOSITORY='fixture/AEGIS-Intelligence',GITHUB_SHA='a'*40,GITHUB_REF='refs/heads/main',GITHUB_OUTPUT=str(output),AEGIS_PUBLIC_KEY=(self.keys/'verification.pub').read_text().strip(),FAKE_GH_STATE=str(state),FAKE_GH_SCENARIO=scenario,FAKE_ASSETS=str(assets))
  return work,state,env
 def run_script(self,name,scenario='success',mutate=None):
  work,state,env=self.setup_run(scenario)
  if mutate:mutate(work,env)
  r=subprocess.run(['bash',str(ROOT/'scripts'/name)],cwd=work,env=env,capture_output=True,text=True)
  return r,json.loads(state.read_text()),work
 def test_verified_draft_publication(self):
  r,s,_=self.run_script('publish-release.sh');self.assertEqual(r.returncode,0,r.stderr);self.assertTrue(s['published']);self.assertTrue(s['downloaded'])
 def test_failed_upload_validation_never_publishes(self):
  r,s,_=self.run_script('publish-release.sh','corrupt_download');self.assertNotEqual(r.returncode,0);self.assertTrue(s['draft']);self.assertFalse(s.get('published',False))
 def test_existing_tag_or_release_never_overwritten(self):
  for scenario in ['existing','existing_tag']:
   r,s,_=self.run_script('publish-release.sh',scenario);self.assertNotEqual(r.returncode,0);self.assertFalse(s.get('draft',False))
 def test_wrong_key_or_untrusted_branch_has_no_github_writes(self):
  for mutate in [lambda w,e:e.update(AEGIS_PUBLIC_KEY=base64.b64encode(b'x'*32).decode()),lambda w,e:e.update(GITHUB_REF='refs/heads/feature')]:
   r,s,_=self.run_script('publish-release.sh',mutate=mutate);self.assertNotEqual(r.returncode,0);self.assertEqual(s['calls'],[])
 def test_api_failure_is_not_bootstrap(self):
  r,s,_=self.run_script('publish-release.sh','api_error');self.assertNotEqual(r.returncode,0);self.assertFalse(s.get('draft',False))
  r,s,_=self.run_script('fetch-previous.sh','previous_error');self.assertNotEqual(r.returncode,0)
 def test_previous_and_bootstrap(self):
  r,s,w=self.run_script('fetch-previous.sh');self.assertEqual(r.returncode,0,r.stderr);self.assertEqual((w/'previous/manifest.json').read_bytes(),(self.release/'manifest.json').read_bytes());self.assertIn('previous=previous',(w/'output.txt').read_text())
  r,s,w=self.run_script('fetch-previous.sh','bootstrap');self.assertEqual(r.returncode,0,r.stderr);self.assertEqual((w/'output.txt').read_text(),'previous=\n')
if __name__=='__main__':unittest.main(verbosity=2)
