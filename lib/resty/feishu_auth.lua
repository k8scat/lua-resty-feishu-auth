-- Copyright (C) K8sCat<k8scat@gmail.com>
-- https://open.feishu.cn/document/ukTMukTMukTM/uETOwYjLxkDM24SM5AjN#9f534005

local json = require("cjson")
local jwt = require("resty.jwt")
local http = require("resty.http")
local ngx = require("ngx")

local ok, new_tab = pcall(require, "table.new")
if not ok or type(new_tab) ~= "function" then
    new_tab = function (narr, nrec) return {} end
end

local jwt_header_alg = "HS256"

local _M = new_tab(0, 30)

_M._VERSION = "0.0.1"

_M.app_id = ""
_M.app_secret = ""
_M.callback_uri = "/feishu_auth_callback"
_M.app_domain = ""

_M.jwt_secret = ""
_M.jwt_expire = 28800 -- 8小时

_M.logout_uri = "/feishu_auth_logout"
_M.logout_redirect = "/"

_M.cookie_key = "feishu_auth_token"

_M.ip_blacklist = {}
_M.uri_whitelist = {}
_M.department_whitelist = {}

local function concat_tabs(t1, t2)
    if not t2 then
        return t1
    end

    for k, v in pairs(t2) do
        t1[k] = t2[k]
    end
    return t1
end

local function http_get(url, query, headers)
    local request = http.new()
    request:set_timeout(10000)
    return request:request_uri(url, {
        method = "GET",
        query = query,
        headers = headers,
        ssl_verify = false
    })
end

local function http_post(url, body, headers)
    local request = http.new()
    request:set_timeout(10000)

    headers = concat_tabs({
        ["Content-Type"] = "application/json; charset=utf-8",
    }, headers)
    ngx.log(ngx.ERR, json.encode(headers))
    if body then
        body = json.encode(body)
    end
    return request:request_uri(url, {
        method = "POST",
        body = body,
        headers = headers,
        ssl_verify = false
    })
end

local function has_value(tab, val)
    for i=1, #tab do
        if tab[i] == val then
            return true
        end
    end
    return false
end

-- 获取 tenant_access_token（企业自建应用）
-- https://open.feishu.cn/document/ukTMukTMukTM/uIjNz4iM2MjLyYzM
function _M:get_app_access_token()
    local url = "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal/"
    local body = {
        app_id = self.app_id,
        app_secret = self.app_secret
    }
    local res, err = http_post(url, body, nil)
    if not res then
        return nil, err
    end
    if res.status ~= 200 then
        return nil, res.body
    end
    local data = json.decode(res.body)
    if data["code"] ~= 0 then
        return nil, res.body
    end
    return data["tenant_access_token"]
end

-- 使用 code 获取用户信息
-- https://open.feishu.cn/document/ukTMukTMukTM/uEDO4UjLxgDO14SM4gTN
function _M:get_login_user(code)
    local app_access_token, err = self:get_app_access_token()
    if not app_access_token then
        return nil, "get app_access_token failed: " .. err
    end
    local url = "https://open.feishu.cn/open-apis/authen/v1/access_token"
    local headers = {
        Authorization = "Bearer " .. app_access_token
    }
    local body = {
        grant_type = "authorization_code",
        code = code
    }
    ngx.log(ngx.ERR, json.encode(body))
    local res, err = http_post(url, body, headers)
    if not res then
        return nil, err
    end
    local data = json.decode(res.body)
    if data["code"] ~= 0 then
        return nil, res.body
    end
    return data["data"]
end

-- 获取单个用户信息
-- https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/contact-v3/user/get
function _M:get_user(user_access_token, open_id)
    local url = "https://open.feishu.cn/open-apis/contact/v3/users/" .. open_id
    local headers = {
        Authorization = "Bearer " .. user_access_token
    }
    local res, err = http_get(url, nil, headers)
    if not res then
        return nil, err
    end
    local data = json.decode(res.body)
    if data["code"] ~= 0 then
        return nil, res.body
    end
    return data["data"]["user"], nil
end

function _M:sso()
    local callback_url = ngx.var.scheme .. "://" .. self.app_domain .. self.callback_uri
    local redirect_url = ngx.var.scheme .. "://" .. self.app_domain .. ngx.var.request_uri
    local args = ngx.encode_args({
        app_id = self.app_id,
        redirect_uri = callback_url,
        state = redirect_url
    })
    return ngx.redirect("https://open.feishu.cn/open-apis/authen/v1/index?" .. args)
end

function _M:clear_token()
    ngx.header["Set-Cookie"] = self.cookie_key .. "=; expires=Thu, 01 Jan 1970 00:00:00 GMT"
end

function _M:logout()
    self:clear_token()
    return ngx.redirect(self.logout_redirect)
end

function _M:verify_token()
    local token = ngx.var.cookie_feishu_auth_token
    if not token then
        return nil, "token not found"
    end

    local result = jwt:verify(self.jwt_secret, token)
    ngx.log(ngx.ERR, "jwt_obj: ", json.encode(result))
    if result["valid"] then
        local payload = result["payload"]
        if payload["department_ids"] and payload["open_id"] then
            return payload
        end
        return nil, "invalid token: " .. json.encode(result)
    end
    return nil, "invalid token: " .. json.encode(result)
end

function _M:sign_token(user)
    local open_id = user["open_id"]
    if not open_id or open_id == "" then
        return nil, "invalid open_id"
    end
    local department_ids = user["department_ids"]
    if not department_ids or type(department_ids) ~= "table" then
        return nil, "invalid department_ids"
    end

    return jwt:sign(
        self.jwt_secret,
        {
            header = {
                typ = "JWT",
                alg = jwt_header_alg,
                exp = ngx.time() + self.jwt_expire
            },
            payload = {
                open_id = open_id,
                department_ids = json.encode(department_ids)
            }
        }
    )
end

function _M:check_user_access(user)
    if type(self.department_whitelist) ~= "table" then
        ngx.log(ngx.ERR, "department_whitelist is not a table")
        return false
    end
    if #self.department_whitelist == 0 then
        return true
    end

    local department_ids = user["department_ids"]
    if not department_ids or department_ids == "" then
        return false
    end
    if type(department_ids) ~= "table" then
        department_ids = json.decode(department_ids)
    end
    for i=1, #department_ids do
        if has_value(self.department_whitelist, department_ids[i]) then
            return true
        end
    end
    return false
end

function _M:sso_callback()
    local request_args = ngx.req.get_uri_args()
    if not request_args then
        ngx.log(ngx.ERR, "sso callback no args")
        return ngx.exit(ngx.HTTP_BAD_REQUEST)
    end
    local code = request_args["code"]
    if not code then
        ngx.log(ngx.ERR, "sso callback code not found")
        return ngx.exit(ngx.HTTP_BAD_REQUEST)
    end
    ngx.log(ngx.ERR, "sso callback code: ", code)

    local login_user, err = self:get_login_user(code)
    if not login_user then
        ngx.log(ngx.ERR, "get login user failed: ", err)
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
    ngx.log(ngx.ERR, "login user: ", json.encode(login_user))

    local user, err = self:get_user(login_user["access_token"], login_user["open_id"])
    if not user then
        ngx.log(ngx.ERR, "get user failed: ", err)
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
    ngx.log(ngx.ERR, "user: ", json.encode(user))

    if not self:check_user_access(user) then
        ngx.log(ngx.ERR, "user access not permitted")
        return self:sso()
    end

    local token, err = self:sign_token(user)
    if err ~= nil then
        ngx.log(ngx.ERR, "sign token failed: ", err)
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
    ngx.header["Set-Cookie"] = self.cookie_key .. "=" .. token

    local redirect_url = request_args["state"]
    if not redirect_url or redirect_url == "" then
        redirect_url = "/"
    end
    return ngx.redirect(redirect_url)
end

function _M:auth()
    local request_uri = ngx.var.uri
    ngx.log(ngx.ERR, "request uri: ", request_uri)

    if has_value(self.uri_whitelist, request_uri) then
        ngx.log(ngx.ERR, "uri in whitelist: ", request_uri)
        return
    end

    local request_ip = ngx.var.remote_addr
    if has_value(self.ip_blacklist, request_ip) then
        ngx.log(ngx.ERR, "forbided ip: ", request_ip)
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end

    if request_uri == self.logout_uri then
        return self:logout()
    end

    local payload, err = self:verify_token()
    if payload then
        if self:check_user_access(payload) then
            return
        end

        ngx.log(ngx.ERR, "user access not permitted")
        self:clear_token()
        return self:sso()
    end
    ngx.log(ngx.ERR, "verify token failed: ", err)

    if request_uri ~= self.callback_uri then
        return self:sso()
    end
    return self:sso_callback()
end

return _M
