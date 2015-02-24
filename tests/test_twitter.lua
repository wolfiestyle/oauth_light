#!/usr/bin/env lua
package.path = "../src/?.lua;" .. package.path
local oauth = require "oauth_light"
local curl = require "cURL"
local pl_config = require "pl.config"
local pl_file = require "pl.file"
local pretty = require "pl.pretty"
local tablex = require "pl.tablex"
local json = require "dkjson"

local config = assert(pl_config.read "twitter_app_keys") -- file with consumer_key and consumer_secret
config.sig_method = "HMAC-SHA1"
config.use_auth_header = true

local function table_writer(t, data) t[#t + 1] = data end

local function do_request(method, url, args, multipart)
    print("-- oauth request: " .. method .. " " .. url)
    local req_url, req_body, req_headers = oauth.build_request(method, url, args, config, multipart)

    local resp = {}

    local req = curl.easy()
    :setopt_customrequest(method)
    :setopt_url(req_url)
    :setopt_httpheader(tablex.pairmap(function(k, v) return k .. ": " .. v end, req_headers))
    :setopt_writefunction(table_writer, resp)
    --:setopt_headerfunction(table_writer, headers)
    if req_body then
        if multipart then
            local form = curl.form()
            for k, v in pairs(req_body) do
                if type(v) == "table" then
                    form:add_buffer(k, v.filename, v.data)
                else
                    form:add_content(k, v)
                end
            end
            req:setopt_httppost(form)
        else
            req:setopt_postfields(req_body)
        end
    end
    local code = req:perform():getinfo(curl.INFO_RESPONSE_CODE)
    req:close()
    assert(code == 200, code)

    return table.concat(resp)
end

local keys = pl_config.read "twitter_auth"

if not keys then
    local body = do_request("POST", "https://api.twitter.com/oauth/request_token", { oauth_callback = "oob" })
    local token = oauth.form_decode_pairs(body)
    print("-- request token --\n" .. pretty.write(token))
    tablex.update(config, token)

    local auth_url = "https://api.twitter.com/oauth/authorize?oauth_token=" .. oauth.url_encode(token.oauth_token)
    io.write("-- auth url: " .. auth_url .. "\n-- enter pin: ")
    local pin = assert(io.read():match("%d+"), "invalid number")

    local body = do_request("POST", "https://api.twitter.com/oauth/access_token", { oauth_verifier = pin })
    keys = oauth.form_decode_pairs(body)
    print("-- access token --\n" .. pretty.write(keys))

    local ok, err = pl_file.write("twitter_auth", table.concat(tablex.pairmap(function(k, v) return k.." = "..v end, keys), "\n") .. "\n")
    if not ok then print("-- Warning: couldn't write twitter_auth file: " .. err) end
end

tablex.update(config, keys)

local body = do_request("GET", "https://api.twitter.com/1.1/account/verify_credentials.json")
local data, _, err = json.decode(body)
assert(data, err)
print("-- user info --\n" .. pretty.write(data))
--[[
local img_data = assert(pl_file.read "image.jpg")
local body = do_request("POST", "https://api.twitter.com/1.1/statuses/update_with_media.json",
    { status = "test multipart", ["media[]"] = { filename = "image.jpg", data = img_data } }, true)
local data, _, err = json.decode(body)
assert(data, err)
print("-- tweet --\n" .. pretty.write(data))
]]
