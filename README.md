# lua-resty-feishu-auth

适用于 OpenResty / ngx_lua 的基于[飞书](https://www.feishu.cn/)组织架构的登录认证

## 使用

### 安装 OpenResty

参考: https://k8scat.com/posts/linux/install-openresty-on-ubuntu-from-source-code/

### 下载

```bash
cd /usr/local/openresty/site/lualib
git clone https://github.com/k8scat/lua-resty-http.git
git clone https://github.com/k8scat/lua-resty-jwt.git
git clone https://github.com/k8scat/lua-resty-feishu-auth.git
```

### 配置

#### http 配置

```conf
http {
    lua_package_path "/usr/local/openresty/site/lualib/lua-resty-feishu-auth/lib/?.lua;/usr/local/openresty/site/lualib/lua-resty-jwt/lib/?.lua;/usr/local/openresty/site/lualib/lua-resty-jwt/vendor/?.lua;/usr/local/openresty/site/lualib/lua-resty-http/lib/?.lua;;";
}
```

#### server 配置

```
server {
    listen 443 ssl;
    server_name feishu-auth.example.com;
    resolver 8.8.8.8;
    
    ssl_certificate /usr/local/openresty/cert/feishu-auth.example.com.crt;
    ssl_certificate_key /usr/local/openresty/cert/feishu-auth.example.com.key;
    ssl_session_cache shared:SSL:1m;
    ssl_session_timeout 5m;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers AESGCM:HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers  on;
    lua_ssl_verify_depth 2;
    lua_ssl_trusted_certificate /etc/pki/tls/certs/ca-bundle.crt;
    if ($time_iso8601 ~ "^(\d{4})-(\d{2})-(\d{2})T(\d{2})") {
        set $year $1;
        set $month $2;
        set $day $3;
    }
    access_log logs/feishu-auth.example.com_access_$year$month$day.log main;
    error_log logs/feishu-auth.example.com_error_$year$month$day.log;

    access_by_lua_block {
        local feishu_auth = require "resty.feishu_auth"
        feishu_auth.app_id = ""
        feishu_auth.app_secret = ""
        feishu_auth.callback_uri = "/feishu_auth_callback"
        feishu_auth.logout_uri = "/feishu_auth_logout"
        feishu_auth.app_domain = "feishu-auth.example.com"

        feishu_auth.jwt_secret = "thisisjwtsecret"

        feishu_auth.ip_blacklist = {"47.1.2.3"}
        feishu_auth.uri_whitelist = {"/"}
        feishu_auth.department_whitelist = {"0"}

        feishu_auth:auth()
    }
}

server {
    listen 80;
    server_name feishu-auth.example.com;

    location / {
        rewrite ^/(.*) https://$server_name/$1 redirect;
    }
}
```

### 配置说明

- `app_id` 用于设置飞书企业自建应用的 `App ID`
- `app_secret` 用于设置飞书企业自建应用的 `App Secret`
- `callback_uri` 用于设置飞书网页登录后的回调地址（需在飞书企业自建应用的安全设置中设置重定向 URL）
- `logout_uri` 用于设置登出地址
- `app_domain` 用于设置访问域名（需和业务服务的访问域名一致）
- `jwt_secret` 用于设置 JWT secret
- `ip_blacklist` 用于设置 IP 黑名单
- `uri_whitelist` 用于设置地址白名单，例如首页不需要登录认证
- `department_whitelist` 用于设置部门白名单（字符串），默认不限制部门

### 应用权限说明

- 获取部门基础信息
- 获取部门组织架构信息
- 以应用身份读取通讯录
- 获取用户组织架构信息
- 获取用户基本信息

## 依赖模块

- [lua-resty-http](https://github.com/ledgetech/lua-resty-http)
- [lua-resty-jwt](https://github.com/SkyLothar/lua-resty-jwt)

## 相关项目

- [lua-resty-weauth](https://github.com/k8scat/lua-resty-weauth) 适用于 OpenResty / ngx_lua 的基于[企业微信](https://work.weixin.qq.com/)组织架构的登录认证

## 作者

K8sCat <k8scat@gmail.com>

## 开源协议

[MIT](./LICENSE)
