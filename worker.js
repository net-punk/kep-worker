import ui from "./ui.html";
import newpost from "./markdown.html";
import banuser from "./manager.html";

const PAGE_SIZE = 16
const BASE = 62;

export default {
 async fetch(req, env, ctx) {

  const url = new URL(req.url)
  const path = url.pathname

   if (path === "/index.php" && req.method === "GET"){
	   const manager = url.searchParams.get("manager")
	   if (!manager || manager == "") {
		return new Response(ui, {
			headers: { "content-type": "text/html;charset=UTF-8" }
		});
	   }
	   
	   const auth = await checkBasicAuth(req, env);
	   if (!auth.ok) {
			return new Response("Login required", { status: 403 });
	  }
	  if (manager == "newpost") {
		return new Response(newpost, {
			headers: { "content-type": "text/html;charset=UTF-8" }
		});
	  }
	  if (manager == "banuser") {
		const csrftoken=getCookie(req,"kepcsrf")
		const htmlmangr=banuser.replace("{{ .Tokenk1 }}",csrftoken)
		return new Response(htmlmangr, {
			headers: { "content-type": "text/html;charset=UTF-8" }
		});
	  }
	  return new Response("404 page not found",{status:404})
   }
   
   if (path === "/login")
    return login(req, env)

   if (path === "/me" && req.method === "GET")
    return me(req, env)

   if (path.startsWith("/index/") && req.method === "GET")
    return indexList(req, env, path)

   if (path.startsWith("/v1/"))
     return acceptMsg(req, env, ctx)

   if (path.startsWith("/view/")) {
    if (req.method === "GET")
     return viewThread(req, env, path)

    if (req.method === "POST") {
		const auth = await checkBasicAuth(req, env);
		if (!auth.ok) {
			return new Response("Login required", { status: 403 });
		}
		return postReply(req, env, ctx, path)
	}
   }
   
   if (path === "/index.php" && req.method === "POST") {
	   const auth = await checkBasicAuth(req, env);
	   if (!auth.ok) {
			return new Response("access deny", { status: 403 });
	  }
		return newTopic(req, env, ctx)
   }
   
   if (path === "/manager")
    return manager(env,req)

   return new Response("404 page not found",{status:404})

 }
}

function json(data){

 return new Response(JSON.stringify(data),{
  headers:{ "content-type":"application/json"}
 })

}

function now(){
 return Math.floor(Date.now()/1000)
}

function rand(){
 return crypto.randomUUID().replaceAll("-","")
}

function getCookie(request, name) {
  const cookie = request.headers.get("Cookie");
  if (!cookie) return null;
  const match = cookie.match(new RegExp(`(^| )${name}=([^;]+)`));
  return match ? match[2] : null;
}

async function checkBasicAuth(req, env) {
  const csrftoken=getCookie(req,"kepcsrf");
  const client_sess=getCookie(req,"kepsess")
  if (csrftoken && client_sess) {
  const [c_sess,deadline] = client_sess.split("_");
  if (Number(deadline) > now()) {
  const server_sess = await sha256sum(env.USER+";"+env.PASSWD+";"+csrftoken+";"+deadline);
  if (server_sess===c_sess) {
	  return { ok: true };
  }}
  }
  
  const auth = req.headers.get("Authorization");
  if (!auth || !auth.startsWith("Basic ")) {
    return { ok: false, status: 401 };
  }

  try {
    const encoded = auth.slice(6);
    const decoded = atob(encoded);

    const idx = decoded.indexOf(":");
    if (idx === -1) return { ok: false, status: 403 };

    const username = decoded.slice(0, idx);
    const password = decoded.slice(idx + 1);

    if (username === env.USER && password === env.PASSWD) {
      return { ok: true };
    }

    return { ok: false, status: 403 };
  } catch (e) {
    return { ok: false, status: 403 };
  }
}

function mask(str, key = 0) {
  const ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  let out = "";
  for (let i = 0; i < str.length; i++) {
    let v = (str.charCodeAt(i) + key) & 0xff;
    const a = Math.floor(v / BASE);
    const b = v % BASE;
    out += ALPHABET[a] + ALPHABET[b];
  }
  return out;
}

function unmask(str, key = 0) {
  const ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  let out = "";
  for (let i = 0; i < str.length; i += 2) {
    const a = ALPHABET.indexOf(str[i]);
    const b = ALPHABET.indexOf(str[i + 1]);
    const v = a * BASE + b;
    const orig = (v - key + 256) & 0xff;
    out += String.fromCharCode(orig);
  }
  return out;
}

function mask_token(env,str) {
  const keystr=env.privkey_base64;
  const key=(keystr.charCodeAt(0)+keystr.charCodeAt(1)+keystr.charCodeAt(2)+keystr.charCodeAt(3)+keystr.charCodeAt(4))& 0xff;
  const half = Math.floor(str.length / 2);
  let out = str.slice(0, half)+"******";
  let out1= str.slice(half, str.length)
  out1=mask(out1,key)
  return out+out1;
}

function unmask_token(env,str) {
  const keystr=env.privkey_base64;
  const key=(keystr.charCodeAt(0)+keystr.charCodeAt(1)+keystr.charCodeAt(2)+keystr.charCodeAt(3)+keystr.charCodeAt(4))& 0xff;
  const pos = str.indexOf("******");
  if (pos <= 0){
	  return "Null"
  }
  let out = str.slice(0, pos);
  const str1 = str.slice(pos + 6);
  let out1=unmask(str1,key)
  return out+out1;
}

async function manager(env,request) {
	const auth = await checkBasicAuth(request, env);
	if (!auth.ok) {
		return new Response("access deny", { status: 403 });
	}
    if (request.method === "POST") {
	  const csrftoken=getCookie(request,"kepcsrf")
      const data = await request.json();

      const req = data.req;
      const act = data.act;
      const url1 = data.url;
	  const csrf1 = data.csrf;
	  
	  if (csrf1 !== csrftoken) {
		  return new Response("csrf token err", { status: 400 });
	  }
	 
	if (req=="list"){
  const apiMap = await env.NerAPI.get("api", "json") || {};
  const url = [];
  const token = [];

  for (const [u, t] of Object.entries(apiMap)) {
    url.push(u);
	const mtoken = mask_token(env,t);
    token.push(mtoken);
  }

  const result = {
    state: "OK",
    data: token,
    url: url
  };

  return new Response(JSON.stringify(result), {
    headers: { "Content-Type": "application/json" }
  });
	}
	 
	if (req=="add_neighbor"){
		if (!url1.startsWith("http")) {
			return json({state:"neighbor url not start with http?://"});
		}
		let url = await env.NerAPI.get("key:"+act);
		if (url) {
			return json({state:"token is exist"});
		}
		await env.NerAPI.put("key:"+act,url1);
		
		let apiMap = await env.NerAPI.get("api", "json") || {};
		
		apiMap[url1] = act;

		await env.NerAPI.put("api", JSON.stringify(apiMap));
		
		return json({state:"OK"})
	}
  
	if (req=="del_neighbor") {
		const ctoken=unmask_token(env,act);
		let url = await env.NerAPI.get("key:"+ctoken)
		if (!url) {
			return json({state:"token not exist"})
		}
		
		let apiMap = await env.NerAPI.get("api", "json") || {};
		delete apiMap[url];
		await env.NerAPI.put("api", JSON.stringify(apiMap));
		
		await env.NerAPI.delete("key:"+ctoken);
		
		return json({state:"OK"})
	}
	
	if (req=="ban"){
		let url = await env.NerAPI.get("ban:"+act);
		if (url) {
			return json({state:"user is banned"});
		}
		await env.NerAPI.put("ban:"+act,url1);
		
		return json({state:"OK"})
	}
	
	if (req=="unban"){
		let url = await env.NerAPI.get("ban:"+act);
		if (!url) {
			return json({state:"user not ban"});
		}
		await env.NerAPI.delete("ban:"+act);
		
		return json({state:"OK"})
	}
	
	if (req=="perm"){
		const num1=parseInt(url1)
		if (Number.isNaN(num1)) {
			return json({state:"new perm is null"})
		}
		const result = await changePost(env,act,1,num1)
		if (result){
			return json({state:"set-perm: OK"})
		}else{
			return json({state:"set-perm: fail"})
		}
	}
	
	if (req=="tag"){
		const num1=parseInt(url1)
		if (Number.isNaN(num1)) {
			return json({state:"new tag invalid"})
		}
		const result = await changePost(env,act,2,num1)
		if (result){
			return json({state:"OK"})
		}else{
			return json({state:"set-tag: fail"})
		}
	}
	
	return json({state:"not realize"})
    }

    return new Response("Only POST allowed", { status: 403 });
}
async function changePost(env,topichex,cmd,set){
	
 let thread = await env.FORUM.get("thread:"+topichex,"json")

 if(!thread)
  return false

 const post = thread.find(p=>p.hex===topichex)

 if(!post)
	return false

 let changed=false;
 
 if (cmd===1){
	if (set===0) {
		changed=true;
		post.extperm=0;
		delete post.extperm
	} else if (set===1) {
		changed=true;
		post.extperm=1;
	}
 } else if (cmd===2){
	if (set!==0) {
		changed=true;
		post.tag = set;
	}
 }
	
 if (changed){
  await env.FORUM.put(
   "thread:"+topichex,
   JSON.stringify(thread)
  )
  if (cmd===2){await updateIndexReply(env,topichex,"","",set);}
 }
 
  return changed;
}


async function login(req,env){
	const auth = await checkBasicAuth(req, env);
		if (!auth.ok) {
			if (auth.status === 401) {
			return new Response("Unauthorized", {
				status: 401,
				headers: { "WWW-Authenticate": 'Basic realm="Login required"' }
			});
			}
			return new Response("Forbidden", { status: 403 });
		}
const domain = env.domain;
const csrftoken=rand();
const deadline = String(now()+604800);

const session = await sha256sum(env.USER+";"+env.PASSWD+";"+csrftoken+";"+deadline);

const headers = new Headers();
headers.append("content-type","application/json");
headers.append("Set-Cookie","kepcsrf="+csrftoken+"; Path=/; Max-Age=604800; HttpOnly; Secure; SameSite=Lax");
headers.append("Set-Cookie","kepsess="+session+"_"+deadline+"; Path=/; Max-Age=604800; HttpOnly; Secure; SameSite=Lax")

return new Response(JSON.stringify({
  status:1,
  user:domain,
  nonce: csrftoken
 }),{ headers })
}

async function sha256sum(text) {
  const data = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
  return hashHex;
}

async function me(req,env){
	const auth = await checkBasicAuth(req, env);
		if (!auth.ok) {
			return json({status:0})
		}
		const domain = env.domain;
		const csrftoken=getCookie(req,"kepcsrf")
 return json({
  status:1,
  user:domain,
  nonce: csrftoken
 })
}

async function indexList(req,env,path){

 const page = parseInt(path.split("/")[3]) || 1

 const list = await env.FORUM.get("index:list","json") || []

 const sorted = [...list].sort((a,b)=>b.lasttime-a.lasttime)

 const start = (page-1)*PAGE_SIZE
 const end = start+PAGE_SIZE

 const slice = sorted.slice(start,end)

 const out = slice.map(i=>({

  hex:i.hex,
  own:i.own,
  lastview:i.title,
  reply:i.reply,
  tag:i.tag,
  typeid:i.perm,
  meta:i.meta,
  lasttime:i.lasttime

 }))

 return json(out)

}

async function viewThread(req,env,path){

 const hex = path.split("/")[3]

 const data = await env.FORUM.get("thread:"+hex,"json")

 if(!data)
  return new Response("post not found",{status:404})

 const firstUser = data[0]?.user

 const out = data.map(p=>({

  ...p,
  me:p.user===firstUser

 }))
 let experm_set=false;
 if ('extperm' in (data[0] || {})) {
	 if (data[0]?.extperm === 1){experm_set=true;}
 }
 if ((data[0]?.perm !== 0)||experm_set) {
	 const auth = await checkBasicAuth(req, env);
		if (!auth.ok) {
			return new Response("Login required", { status: 403 });
		}
 }

 return json(out)

}

async function postReply(req,env,ctx,path){

 const pointtohex = path.split("/")[3]

 const body = await req.json()

 const text = body.post_payload
 const nonce = body.nonce
 
 const csrftoken=getCookie(req,"kepcsrf")
 
 if (!csrftoken || !nonce || !nonce.startsWith(csrftoken)) {
	 return new Response("post format err")
 }

 if(!text || text.length>20000)
  return json({status:"post format err"})

 let thread = await env.FORUM.get("thread:"+pointtohex,"json")

 const time = now()

 if(!thread){
  return json({status:"post not found"})
 }
 const domain=env.domain
 
 const newdata = await makedata(env,domain,text,pointtohex,0,0);
 
 if (!newdata.ok) {
	 return json({status:"key noy set"})
 }
 const id = thread.length+1

 const post = {

  id:id,
  user:domain,
  meta:"",
  post:text,
  post_time:time,
  first_time:time,
  tag:0,
  perm: 0,
  hex:newdata.hex

 }

 thread.push(post)

 await env.FORUM.put(
  "thread:"+pointtohex,
  JSON.stringify(thread)
 )

  await updateIndexReply(env,pointtohex,time,"")
	ctx.waitUntil(
		sendMsg(env,newdata.payload)
	);
 return json({status:"ok"})

}

async function appendIndex(env,item){

 let list = await env.FORUM.get("index:list","json")

 if(!list)
  list=[]

 list.push(item)

 await env.FORUM.put(
  "index:list",
  JSON.stringify(list)
 )

}

async function updateIndexReply(env,hex,time,title1,tag1=0){

 let list = await env.FORUM.get("index:list","json")

 if(!list) return

 for(let i=list.length-1;i>=0;i--){

  if(list[i].hex===hex){

   if (time!==""){
   list[i].reply++
   list[i].lasttime=time
   }
   if (title1!==""){
   list[i].title=title1
   }
   if (tag1!==0){
   list[i].tag=tag1
   }
   break

  }

 }

 await env.FORUM.put(
  "index:list",
  JSON.stringify(list)
 )

}

async function newTopic(req,env,ctx){

 const body = await req.text()
 const form = new URLSearchParams(body)

 const markdown = form.get("markdown") || ""
 const tag = parseInt(form.get("tag") || "0")
 const typeid = parseInt(form.get("typeid") || "0")
 const nonce = form.get("nonce") || ""

 const pointto = form.get("pointto")
 const pointtoroot = form.get("pointtoroot")
 
 const csrftoken=getCookie(req,"kepcsrf")
 
 if (!csrftoken || !nonce || !nonce.startsWith(csrftoken)) {
	 return new Response("post format err")
 }

 if(!markdown || markdown.length>40000)
	return new Response("post format err")

 const time = now()
 const domain=env.domain

 if(pointto){
	
	let topicpoint=pointto
	if (pointtoroot != null) {
	  topicpoint=pointtoroot
	}
  let thread = await env.FORUM.get("thread:"+topicpoint,"json")

  if(!thread)
	return new Response("topic not found")

  const post = thread.find(p=>p.hex===pointto)

  if(!post)
	  return new Response("post not found")

  post.post = markdown
  post.post_time = time
  post.perm = typeid
  
  let newpoint=pointto
  if (pointtoroot != null) {
	  newpoint=newpoint+pointtoroot
  }
 const newdata = await makedata(env,domain,markdown,newpoint,typeid,65534);
 
 if (!newdata.ok) {
	 return new Response("post format err")
 }

  await env.FORUM.put(
   "thread:"+topicpoint,
   JSON.stringify(thread)
  )
  
  	ctx.waitUntil(
		sendMsg(env,newdata.payload)
	);
	let tt="";
	if (topicpoint==pointto) {
		const i = markdown.indexOf('\n');
		tt =i === -1 ? markdown : markdown.slice(0, i);
		if (!tt.trimStart().startsWith('#')) {tt=domain +"'s post";}
		tt = tt.replace(/^#+/, '');
		tt = tt.trimStart();
	}
 
 await updateIndexReply(env,topicpoint,time,tt)
  return new Response("post ok")

 }
 
 const newdata = await makedata(env,domain,markdown,"",typeid,tag);
 
 if (!newdata.ok) {
	 return new Response("post format err")
 }

 const hex = newdata.hex

 const post = {

  id:1,
  user:domain,
  meta:"",
  post:markdown,
  post_time:time,
  first_time:time,
  tag:tag,
  hex:hex,
  perm:typeid

 }

 const thread=[post]

 await env.FORUM.put(
  "thread:"+hex,
  JSON.stringify(thread)
 )
 
 const i = markdown.indexOf('\n');
 let tt =i === -1 ? markdown : markdown.slice(0, i);
 if (!tt.trimStart().startsWith('#')) {tt=domain +"'s post";}
 tt = tt.replace(/^#+/, '');
 tt = tt.trimStart();

 await appendIndex(env,{
  hex:hex,
  tag:tag,
  lasttime:time,
  reply:0,
  own:domain,
  meta:"",
  title:tt
 })

	ctx.waitUntil(
		sendMsg(env,newdata.payload)
	);

 return new Response("post ok")

}

async function sendMsg(env, bodybuf,skiptoken="") {
    let apiMap = await env.NerAPI.get("api", "json") || {};
    let str = "";
    for (const [url, token] of Object.entries(apiMap)) {
      if (token===skiptoken) continue;
	  let url1=url+"/v1/messages";
	  url1 = url1.replace(/\/\/+/g, '/');
      let res = await fetch(url1, {
        method: "POST",
        headers: {
          "Content-Type": "application/octet-stream",
		  "X-Msg-Type": "data",
          "Authorization": "Bearer " + token
        },
        body: bodybuf
      });
      str += `url=${url1} status=${res.status}\n`;
    }
	console.log("debug::", str);
}

function hexToUint8Array(hex) {
  if (hex.length % 2 !== 0) {
    throw new Error("invalid hex");
  }

  const arr = new Uint8Array(hex.length / 2);

  for (let i = 0; i < arr.length; i++) {
    arr[i] = parseInt(hex.substr(i * 2, 2), 16);
  }

  return arr;
}

async function makedata(env, username, text, pointto, perm, tags) {

  const encoder = new TextEncoder();

  const domain = encoder.encode(username);
  const txt = encoder.encode(text);
  const point_to = hexToUint8Array(pointto);

  const domain_len = domain.length;
  const point_to_len = point_to.length;
  const length = txt.length;

  const typeId = perm & 255;
  const tag = tags & 65535;
  const compress_type = 0;

  const tag2 = tag;
  const ttl = 128;

  const mainkey = base64ToUint8(env.mainkey_base64);
  const pkey = base64ToUint8(env.pubkey_base64);
  const signkey = base64ToUint8(env.sigkey_base64);

  const priv64 = base64ToUint8(env.privkey_base64);
  
  if (mainkey==null || pkey==null||signkey==null||priv64==null) {
	return {
	ok: false,
    payload: null,
    hex: ""
	};
  }
  
  const seed = priv64.slice(0, 32);
  const pkcs8 = ed25519SeedToPKCS8(seed);

  const privkey = await crypto.subtle.importKey(
    "pkcs8",
    pkcs8,
    { name: "Ed25519" },
    false,
    ["sign"]
  );

  const fixedLen =
      1 + 1 + 1 + 5 + 2 +
      32 + 32 + 64 +
      1 + 1 + 2 + 1;

  const variableLen =
      domain_len +
      point_to_len +
      length;

  const totalBeforeHash = fixedLen + variableLen;

  const buf = new Uint8Array(totalBeforeHash);
  const view = new DataView(buf.buffer);

  let offset = 0;

  view.setUint8(offset++, 1);
  view.setUint8(offset++, 1);
  view.setUint8(offset++, domain_len);
	
  const timestamp = Math.floor(Date.now() / 1000);
  view.setUint8(offset++, 0);
  view.setUint32(offset, timestamp & 0xffffffff);
  offset += 4;

  view.setUint16(offset, length);
  offset += 2;

  buf.set(mainkey, offset); offset += 32;
  buf.set(pkey, offset); offset += 32;
  buf.set(signkey, offset); offset += 64;

  view.setUint8(offset++, typeId);
  view.setUint8(offset++, point_to_len);
  view.setUint16(offset, tag); offset += 2;
  view.setUint8(offset++, compress_type);

  buf.set(domain, offset); offset += domain_len;
  buf.set(point_to, offset); offset += point_to_len;
  buf.set(txt, offset); offset += length;

  const t_hash_buf = await crypto.subtle.digest("SHA-256", buf);
  const t_hash = new Uint8Array(t_hash_buf);

  const signature = new Uint8Array(
    await crypto.subtle.sign(
      "Ed25519",
      privkey,
      t_hash
    )
  );

  const finalLen =
      buf.length +
      32 +
      64 +
      2 +
      1;

  const finalPayload = new Uint8Array(finalLen);
  const finalView = new DataView(finalPayload.buffer);

  offset = 0;

  finalPayload.set(buf, offset);
  offset += buf.length;

  finalPayload.set(t_hash, offset);
  offset += 32;

  finalPayload.set(signature, offset);
  offset += 64;

  finalView.setUint16(offset, tag2);
  offset += 2;

  finalView.setUint8(offset, ttl);

  return {
	ok: true,
    payload: finalPayload,
    hex: uint8ArrayToHex(t_hash)
  };
}

function ed25519SeedToPKCS8(seed32) {
  const header = new Uint8Array([
    0x30,0x2e,
    0x02,0x01,0x00,
    0x30,0x05,
    0x06,0x03,0x2b,0x65,0x70,
    0x04,0x22,
    0x04,0x20
  ]);

  const pkcs8 = new Uint8Array(header.length + 32);
  pkcs8.set(header, 0);
  pkcs8.set(seed32, header.length);

  return pkcs8;
}

function base64ToUint8(b64) {
  if (!b64 || b64.length < 6) {
	  return null
  }
  b64 = b64.replace(/\s+/g, '');
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    arr[i] = bin.charCodeAt(i);
  }
  return arr;
}

async function acceptMsg(request, env, ctx) {
    if (request.method !== "POST") {
      return new Response("404 page not found", { status: 404 });
    }
	const enableLimit = env.enable_limit == "1"
	const auth = request.headers.get("Authorization")
	if (!auth || !auth.startsWith("Bearer ")) {
		return new Response("404 page not found", { status: 404 });
	}
	
	const apt_token = auth.split(" ")[1]
	
  if (enableLimit){
	const success = await env.NerLimit.limit({ key: apt_token }) //300 Msg /min
    if (!success) {
      return new Response(`429 – rate limit exceeded`, { status: 429 })
    }
  }
	
	let ok = await env.NerAPI.get("key:"+apt_token)
	if (!ok || ok.length < 1){
		return new Response("404 page not found", { status: 404 });
	}
	
	const xtype = request.headers.get("X-Msg-Type");

    if (xtype === "ping") {
      return new Response("+PONG", {
        headers: { "content-type": "text/plain;charset=UTF-8" }
      });
    }
	
	if (xtype !== "data") {
      return new Response("missing X-Msg-Type", { status: 400 });
    }

    const buf = await request.arrayBuffer();
    const parsed = parseMsg(buf);

    if (!parsed) {
      return new Response("invalid request", { status: 403 });
    }
	
	ctx.waitUntil(
		handleMsg(env,parsed,buf,apt_token)
	);
	
	return new Response("+OK"); 
}

async function handleMsg(env,parsed,buf1,skiptoken) {
    const {
	  timestamp,
      domain,
	  point_to,
	  tag,
	  typeId,
      txt,
      mainkey,
      pkey,
      signkey,
      signature,
      t_hash,
      signedPart,
	  tag2,
	  ttl
    } = parsed;
	const disable_offset = env.disable_offset_time == "1"
	if (ttl <=0 || ttl > 200) {
		console.log("out of ttl");
		return;
	}
	const bodybuf = new Uint8Array(buf1);
	bodybuf[bodybuf.length-1]= (ttl-1) & 255
	const now_time = Math.floor(Date.now() / 1000);
	
	let offset_t=now_time - timestamp;
	
	offset_t /= 60;
	
	if (!disable_offset) {
	if (offset_t > 15 || offset_t < -15) {
		console.log("out of time");
		return
	}}
	
	const domain_str = new TextDecoder().decode(domain)
	if (domain_str.length === 0 || domain_str.length > 253) {return;}
	const domainRegex = /^[a-z0-9.-]+$/i;
	if (!domainRegex.test(domain_str)) {
		console.log("invalid domain");
		return;
	}
	
	const domain_ban = await env.NerAPI.get("ban:"+domain_str);
	if (domain_ban){
		console.log("domain is banned");
		return;
	}
	
	let cacheKey = await env.NerAPI.get("keycache:"+domain_str,"json")
	
 if (!cacheKey) {
	let kep = "";
	let des = [];
	const txtRecords = await resolveTxt(domain_str)
	
	if (txtRecords==null) {
		console.log("ns lookup fail");
		return
	}

	for (const txt of txtRecords) {
	if (txt.startsWith("kep=")) {
		if (kep ==="") {kep=txt.slice(4);}
	} else if (txt.startsWith("des=")) {
		des.push(txt.slice(4).toLowerCase());
	}
	}
	
	if (kep ==="") {
		console.log("kep is null");
		return
	}
	
	const keybytes = base32Decode(kep);
	const keyok = equalBytes(keybytes, mainkey);
	if (!keyok) {
		console.log("mainkey not match");
		return
	}
	
	let desok = false;
	const des2 = fnv1a64(pkey);
	for (const des1 of des) {
		if (des1==des2) {
			desok=true
			break;
		}
	}
	if (!desok) {
		console.log("pkey not match");
		return
	}
	
	await env.NerAPI.put("keycache:"+domain_str,JSON.stringify({kep:kep,des:des2}), { expirationTtl: 3600*12 })
	
 } else {
	const kep = cacheKey.kep;
	const des = cacheKey.des;
	const des2 = fnv1a64(pkey);
	
	const keybytes = base32Decode(kep);
	const keyok = equalBytes(keybytes, mainkey);
	if (!keyok) {
		console.log("mainkey not match");
		return
	}
	if (des!==des2) {
		console.log("pkey not match");
		return;
	}
 }

    const mainKeyObj = await crypto.subtle.importKey(
      "raw",
      mainkey,
      { name: "Ed25519" },
      false,
      ["verify"]
    );

    const pKeyObj = await crypto.subtle.importKey(
      "raw",
      pkey,
      { name: "Ed25519" },
      false,
      ["verify"]
    );

    const ok1 = await crypto.subtle.verify(
      "Ed25519",
      mainKeyObj,
      signkey,
      pkey
    );
	
	if (!ok1) {
		console.log("sign err");
		return
	}

    const hashBuf = await crypto.subtle.digest("SHA-256", signedPart);
    const hash = new Uint8Array(hashBuf);

    const okHash = equalBytes(hash, t_hash);
	if (!okHash) {
		console.log("hash err");
		return
	}

    const ok2 = await crypto.subtle.verify(
      "Ed25519",
      pKeyObj,
      signature,
      t_hash
    );
	
	if (!ok2) {
		console.log("sign err2");
		return
	}
	
	if (point_to.length > 1) {
		const hex=uint8ArrayToHex(t_hash)
		const pointto=uint8ArrayToHex(point_to)
		const text = new TextDecoder().decode(txt)
		const addok = await addReply(env,pointto,hex,domain_str,text,tag,typeId)
		if (addok) {
			sendMsg(env,bodybuf,skiptoken);
		}
	} else {
		const hex=uint8ArrayToHex(t_hash)
		const text = new TextDecoder().decode(txt)
		const addok = await addTopic(env,hex,text,tag2,typeId,domain_str)
		if (addok) {
			sendMsg(env,bodybuf,skiptoken);
		}
	}
}


function parseMsg(buf) {
  const view = new DataView(buf);
  const bytes = new Uint8Array(buf);

  let offset = 0;

  const version = view.getUint8(offset); offset += 1;
  if (version !=1){return;}
  const hashtype = view.getUint8(offset); offset += 1;
  if (hashtype !=1){return;}
  const domain_len = view.getUint8(offset); offset += 1;
  
  const timestamp =
    (view.getUint8(offset) * 2 ** 32) +
    view.getUint32(offset + 1);
  offset += 5;

  const length = view.getUint16(offset); offset += 2;

  const mainkey = bytes.slice(offset, offset + 32); offset += 32;
  const pkey = bytes.slice(offset, offset + 32); offset += 32;
  const signkey = bytes.slice(offset, offset + 64); offset += 64;

  const typeId = view.getUint8(offset); offset += 1;
  const point_to_len = view.getUint8(offset); offset += 1;
  const tag = view.getUint16(offset); offset += 2;
  const compress_type = view.getUint8(offset); offset += 1;

  const domain = bytes.slice(offset, offset + domain_len);
  offset += domain_len;

  const point_to = bytes.slice(offset, offset + point_to_len);
  offset += point_to_len;

  const txt = bytes.slice(offset, offset + length);
  offset += length;

  const signedPart = bytes.slice(0, offset);

  const t_hash = bytes.slice(offset, offset + 32);
  offset += 32;

  const signature = bytes.slice(offset, offset + 64);
  offset += 64;

  const tag2 = view.getUint16(offset); offset += 2;
  const ttl = view.getUint8(offset); offset += 1;

  return {
    timestamp,
    domain,
	point_to,
	tag,
	typeId,
    txt,
    mainkey,
    pkey,
    signkey,
    signature,
    t_hash,
    signedPart,
    tag2,
    ttl
  };
}

function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

async function resolveTxt(domain) {
  const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=TXT`;

  const resp = await fetch(url, {
    headers: { "accept": "application/dns-json" }
  });

  if (!resp.ok) {
	  console.log(`DNS query failed: ${resp.status}`);
	return
  }

  const data = await resp.json();

  if (!data.Answer) return;

  return data.Answer
    .filter(r => r.type === 16)
    .map(r => r.data.replace(/^"|"$/g, ""));
}

function base32Decode(input) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const map = {};

  for (let i = 0; i < alphabet.length; i++) {
    map[alphabet[i]] = i;
  }

  input = input.toUpperCase().replace(/=+$/,"");

  let buffer = 0;
  let bits = 0;
  const out = [];

  for (const c of input) {
    const val = map[c];
    if (val === undefined) continue;

    buffer = (buffer << 5) | val;
    bits += 5;

    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >> bits) & 0xff);
    }
  }

  return new Uint8Array(out);
}

function fnv1a64(data) {
  const FNV_PRIME = 1099511628211n;
  const OFFSET_BASIS = 14695981039346656037n;

  let hash = OFFSET_BASIS;

  for (const b of data) {
    hash ^= BigInt(b);
    hash = (hash * FNV_PRIME) & 0xffffffffffffffffn;
  }

  return hash.toString(16).padStart(16, "0");
}

function uint8ArrayToHex(arr) {
  return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
}

async function addReply(env,point_to,selfhex,username,text,tag,perm){
	
 if(!text || text.length>20000)
  return false

 let topichex=point_to;
 let posthex=point_to;
 if (topichex.length > 64) {
	 topichex=topichex.slice(64,topichex.length);
	 posthex=posthex.slice(0,64);
	 if (tag !=65534) {return false; }
 }

 let thread = await env.FORUM.get("thread:"+topichex,"json")

 const time = now()

 if(!thread){
  return false
 }
 
  if(tag ==65534){
	  
  const post = thread.find(p=>p.hex===posthex)

  if(!post)
	  return false

  post.post = text
  post.post_time = time
  post.perm = perm

  await env.FORUM.put(
   "thread:"+topichex,
   JSON.stringify(thread)
  )
	let tt="";
	if (posthex==topichex) {
		const i = text.indexOf('\n');
		tt =i === -1 ? text : text.slice(0, i);
		if (!tt.trimStart().startsWith('#')) {tt=username +"'s post";}
		tt = tt.replace(/^#+/, '');
		tt = tt.trimStart();
	}
 
 await updateIndexReply(env,topichex,time,tt)
  
  return true
 }

 const id = thread.length+1

 const post = {

  id:id,
  user:username,
  meta:"",
  post:text,
  post_time:time,
  first_time:time,
  tag:0,
  perm: 0,
  hex:selfhex

 }

 thread.push(post)

 await env.FORUM.put(
  "thread:"+topichex,
  JSON.stringify(thread)
 )
 
 await updateIndexReply(env,topichex,time,"")

 return true

}

async function addTopic(env,hex,text,tag,perm,username){

 const markdown = text
 const typeid = perm

 const pointto = ""
 const pointtoroot = ""

 if(!markdown || markdown.length>20000)
  return false

 const time = now()
 
 const post = {

  id:1,
  user:username,
  meta:"",
  post:markdown,
  post_time:time,
  first_time:time,
  tag:tag,
  hex:hex,
  perm:typeid

 }

 const thread=[post]

 await env.FORUM.put(
  "thread:"+hex,
  JSON.stringify(thread)
 )
 
 const i = markdown.indexOf('\n');
 let tt =i === -1 ? markdown : markdown.slice(0, i);
 if (!tt.trimStart().startsWith('#')) {tt=username +"'s post";}
 tt = tt.replace(/^#+/, '');
 tt = tt.trimStart();

 await appendIndex(env,{
  hex:hex,
  tag:tag,
  lasttime:time,
  reply:0,
  own:username,
  meta:"",
  title:tt
 })

 return true
}