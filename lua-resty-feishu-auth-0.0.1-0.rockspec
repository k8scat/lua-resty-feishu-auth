package = "lua-resty-feishu-auth"
version = "0.0.1-0"
source = {
   url = "https://github.com/k8scat/lua-resty-feishu-auth",
   tag = "v0.0.1"
}
description = {
   summary = "适用于 OpenResty / ngx_lua 的基于飞书组织架构的登录认证",
   homepage = "https://github.com/k8scat/lua-resty-feishu-auth",
   license = "MIT",
   maintainer = "K8sCat <k8scat@gmail.com>"
}
dependencies = {
   "lua >= 5.1"
}
build = {
   type = "builtin",
   modules = {
      ["resty.feishu_auth"] = "lib/resty/feishu_auth.lua"
   }
}