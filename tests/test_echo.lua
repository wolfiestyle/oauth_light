#!/usr/bin/env lua
package.path = "../src/?.lua;" .. package.path
local oauth = require "oauth_light"
local http = require "socket.http"
local ltn12 = require "ltn12"
local pretty = require "pl.pretty"
local tablex = require "pl.tablex"

local config = {
    consumer_key = "key",
    consumer_secret = "secret",
    sig_method = "HMAC-SHA1",
    --realm = "",
    use_auth_header = true,
}

if config.sig_method == "RSA-SHA1" then
    config.rsa_priv = assert(io.open "term_ie_priv.pem"):read "*a"
end

local function do_request(method, url, args)
    local req_url, req_body, req_headers = oauth.build_request(method, url, args, config)
    print("-- oauth request: " .. method .. " " .. url)
    pretty.dump{
        method = method,
        url = req_url,
        body = req_body,
        headers = req_headers,
    }

    local resp = {}

    local ok, code, headers = http.request{
        method = method,
        url = req_url,
        headers = req_headers,
        source = req_body and ltn12.source.string(req_body) or nil,
        sink = ltn12.sink.table(resp),
    }
    assert(ok, code)

    return table.concat(resp), headers
end

local body = do_request("GET", "http://term.ie/oauth/example/request_token.php", { oauth_callback = "oob" })
local keys = oauth.form_decode_pairs(body)
print("-- request token --\n" .. pretty.write(keys))
assert(keys.oauth_token == "requestkey" and keys.oauth_token_secret == "requestsecret", "request_token failed")
tablex.update(config, keys)

local body = do_request("GET", "http://term.ie/oauth/example/access_token.php")
local keys = oauth.form_decode_pairs(body)
print("-- access token --\n" .. pretty.write(keys))
assert(keys.oauth_token == "accesskey" and keys.oauth_token_secret == "accesssecret", "access_token failed")
tablex.update(config, keys)

local body, headers = do_request("POST", "http://term.ie/oauth/example/echo_api.php", { ["ñandú"] = "proando\nla csm" })
print("-- echo headers --\n" .. pretty.write(headers))
print("-- echo body --\n" .. pretty.write(oauth.form_decode_pairs(body)))
assert(body == "%C3%B1and%C3%BA=proando%0Ala+csm", "echo failed")
