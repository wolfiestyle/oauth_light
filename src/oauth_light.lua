-- Minimal implementation of OAuth 1.0 (RFC 5849)
-- It provides a method for building signed OAuth requests, but it doesn't perform HTTP requests.
-- Author: darkstalker <https://github.com/darkstalker>
-- License: MIT/X11
local assert, error, os_time, pairs, string_char, string_format, table_concat, table_sort, tonumber, tostring, type =
      assert, error, os.time, pairs, string.char, string.format, table.concat, table.sort, tonumber, tostring, type
local base64 = require "base64"
local rand = require "openssl.rand"
local hmac = require "openssl.hmac"
local digest = require "openssl.digest"
local pkey = require "openssl.pkey"

local function url_encode(str)
    return str:gsub("[^%w%-._~]", function(chr)
        return string_format("%%%02X", chr:byte())
    end)
end

local function url_decode(str)
    return str:gsub("%%(%x%x)", function(hex)
        return string_char(tonumber(hex, 16))
    end)
end

local function form_encode(str)
    return str:gsub("[^%w%-._~]", function(chr)
        return chr == " " and "+" or string_format("%%%02X", chr:byte())
    end)
end

local function form_decode(str)
    return url_decode(str:gsub("+", " "))
end

local function to_hex(bin)
    return ("%02x"):rep(#bin):format(bin:byte(1, -1))
end

local function encode_pairs(tbl, encoder)
    local query_pairs = {}
    for k, v in pairs(tbl) do
        query_pairs[#query_pairs + 1] = encoder(k) .. "=" .. encoder(v)
    end
    return table_concat(query_pairs, "&")
end

local function decode_pairs(str, decoder)
    local query_pairs = {}
    for pair in str:gmatch "[^&]+" do
        local k, v = pair:match "^([^=]*)=?(.*)"
        query_pairs[decoder(k)] = decoder(v)
    end
    return query_pairs
end

local scheme_ports = { http = ":80", https = ":443" }

local function parse_url(url)
    local scheme, host, port, path, query = url:match "^(%a[%w%-+.]*)://([^:/]+)(:?%d*)(/?[^?]*)%??([^#]*)"
    if not scheme or port == ":" then
        return nil, "invalid URL"
    end

    scheme = scheme:lower()
    host = host:lower()

    local def_port = scheme_ports[scheme]
    if not def_port then
        return nil, "unsupported scheme " .. scheme
    elseif port == def_port then
        port = ""
    end

    return scheme .. "://" .. host .. port .. path, query
end

local function normalize_query_string(str)
    local query_pairs = {}
    for pair in str:gmatch "[^&]+" do
        local k, v = pair:match "^([^=]*)=?(.*)"
        local dk, dv = url_decode(k), url_decode(v)
        query_pairs[#query_pairs + 1] = url_encode(dk) .. "=" .. url_encode(dv)
    end
    return query_pairs
end

local function signature_base_string(method, url, request)
    local base_url, query = assert(parse_url(url))

    local query_pairs = normalize_query_string(query)
    for k, v in pairs(request) do
        query_pairs[#query_pairs + 1] = url_encode(k) .. "=" .. url_encode(v)
    end
    table_sort(query_pairs)

    return url_encode(method) .. "&" .. url_encode(base_url) .. "&" .. url_encode(table_concat(query_pairs, "&"))
end

local function signature_key(keys)
    return url_encode(keys.consumer_secret) .. "&" .. url_encode(keys.oauth_token_secret or "")
end

local function sign_request(method, url, request, keys)
    local sig_method = request.oauth_signature_method
    local base_string
    if sig_method ~= "PLAINTEXT" then
        request.oauth_nonce = to_hex(rand.bytes(20))
        base_string = signature_base_string(method, url, request)
    end

    if sig_method == "HMAC-SHA1" then
        request.oauth_signature = base64.encode(hmac.new(signature_key(keys), "SHA1"):final(base_string))
    elseif sig_method == "RSA-SHA1" then
        request.oauth_signature = base64.encode(pkey.new(keys.rsa_priv):sign(digest.new("RSA-SHA1"):update(base_string)))
    elseif sig_method == "PLAINTEXT" then
        request.oauth_signature = url_encode(signature_key(keys))
    else
        error "unsupported signature method"
    end
end

local function build_auth_header(request, realm)
    local auth = {}
    if realm then
        auth[1] = 'realm="' .. url_encode(realm) .. '"'
    end
    for k, v in pairs(request) do
        if k:find "^oauth_" then
            auth[#auth + 1] = url_encode(k) .. '="' .. url_encode(v) .. '"'
            request[k] = nil
        end
    end
    return "OAuth " .. table_concat(auth, ",")
end

local function convert_string(x)
    local t = type(x)
    if t == "string" or t == "number" or t == "boolean" then -- non-object types
        return tostring(x)
    end
    return nil, "can't use " .. t .." as value"
end

local function build_request(method, url, args, config, multipart)
    assert(config.consumer_key and config.consumer_secret, "missing consumer key/secret")
    method = method:upper()
    if multipart then
        assert(method == "POST", "multipart requires POST")
        assert(config.use_auth_header, "multipart requires auth header")
    end

    local request = {
        oauth_consumer_key = config.consumer_key,
        oauth_token = config.oauth_token,
        oauth_signature_method = config.sig_method,
        oauth_version = "1.0",
        oauth_timestamp = tostring(os_time()),
    }

    if args and not multipart then
        for k, v in pairs(args) do
            assert(type(k) == "string", "key must be string")
            request[k] = assert(convert_string(v))
        end
    end

    sign_request(method, url, request, config)

    local headers = {}
    if config.use_auth_header then
        headers.Authorization = build_auth_header(request, config.realm)
    end

    local body
    if method == "POST" then
        if multipart then
            body = args -- the user must build the multipart request
        else
            body = encode_pairs(request, form_encode)
            headers["Content-Length"] = #body
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        end
    elseif next(request) ~= nil then
        local query = encode_pairs(request, url_encode)
        local s, e = url:find "%?[^#]*"
        if s then
            url = url:sub(1, e) .. "&" .. query .. url:sub(e+1, #url)
        else
            url = url .. "?" .. query
        end
    end

    return url, body, headers
end

local _M = {
    url_encode = url_encode, url_decode = url_decode,
    form_encode = form_encode, form_decode = form_decode,
    build_request = build_request,
}

function _M.url_encode_pairs(tbl) return encode_pairs(tbl, url_encode) end
function _M.url_decode_pairs(str) return decode_pairs(str, url_decode) end
function _M.form_encode_pairs(tbl) return encode_pairs(tbl, form_encode) end
function _M.form_decode_pairs(str) return decode_pairs(str, form_decode) end

return _M
