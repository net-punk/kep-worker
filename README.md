# kep-worker
cf worker 搭建个人 bbs 论坛

## 部署方法

长话短说

### 1.把这三个文件传到cf worker里面

![](img/worker.png)

### 2.绑定2个KV与1个速率限制器到worker

![](img/kv.png)

### 3.添加下面变量到worker

![](img/kv.png)

变量可以选纯文本与密钥，这里为了示例，就使用纯文本

#### 变量解释

- domain: kep验证域名，联机时候用，单机随便填
- enable_limit: 开启速率限制
- USER: 登录用户名
- PASSWD: 登录密码
- mainkey_base64: `openssl base64 -in mainkey.pub -out mainkey.txt`获取
- pubkey_base64: `openssl base64 -in pkey.pub -out pkey.txt`获取
- privkey_base64: `openssl base64 -in pkey.priv -out privkey.txt`获取
- sigkey_base64: `openssl base64 -in pkey.sig -out pkey.txt`获取

4个base64 key，使用kep-cli就能生成。`kepcli -act gen`，就能生成新的密钥。

mainkey与pubkey的TXT记录，需要绑定在domain上才能联机。单机使用只用填进去就行。