local cjson = require("cjson")

local M = {}

local function isempty(s)
  return s == nil or s == ''
end

local function parseFilters(csvFilters)
  local filters = {}
  if (not (csvFilters == nil)) then
    for pattern in string.gmatch(csvFilters, "[^,]+") do
      table.insert(filters, pattern)
    end
  end
  return filters
end

local function decodeBase64(str)
  local decoded_str = ngx.decode_base64(str)
  if not decoded_str then
    utils.exit(500, "invalid OIDC plugin configuration, base64 string could not be decoded", ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR))
  end
  return decoded_str
end

local function getSessionOpts(jsonStr)
  local sessionOpts = {}
  if (not isempty(jsonStr)) then
    -- TODO Handle JSON parsing errors
    sessionOpts = cjson.decode(jsonStr)
  end
  --set session secret from env. var if present
  local session_secret = os.getenv("OIDC_SESSION_SECRET")
  if (not isempty(session_secret)) then
    sessionOpts.secret = session_secret
  elseif (not isempty(sessionOpts.secret)) then
    sessionOpts.secret = decodeBase64(sessionOpts.secret)
  end

  return sessionOpts
end

function M.get_redirect_uri_path(ngx)
  local function drop_query()
    local uri = ngx.var.request_uri
    local x = uri:find("?")
    if x then
      return uri:sub(1, x - 1)
    else
      return uri
    end
  end

  local function tackle_slash(path)
    local args = ngx.req.get_uri_args()
    if args and args.code then
      return path
    elseif path == "/" then
      return "/cb"
    elseif path:sub(-1) == "/" then
      return path:sub(1, -2)
    else
      return path .. "/"
    end
  end

  return tackle_slash(drop_query())
end

function M.get_options(config, ngx)
  return {
    client_id = config.client_id,
    client_secret = config.client_secret,
    discovery = config.discovery,
    introspection_endpoint = config.introspection_endpoint,
    allow_token_auth = config.allow_token_auth,
    timeout = config.timeout,
    introspection_endpoint_auth_method = config.introspection_endpoint_auth_method,
    bearer_only = config.bearer_only,
    realm = config.realm,
    redirect_uri_path = config.redirect_uri_path or M.get_redirect_uri_path(ngx),
    --redirect_uri = config.redirect_uri or ngx.var.request_uri,
    scope = config.scope,
    response_type = config.response_type,
    ssl_verify = config.ssl_verify,
    token_endpoint_auth_method = config.token_endpoint_auth_method,
    recovery_page_path = config.recovery_page_path,
    filters = parseFilters(config.filters),
    logout_path = config.logout_path,
    redirect_after_logout_uri = config.redirect_after_logout_uri,
    unauth_action = config.unauth_action,
    access_token_header_name = config.access_token_header_name,
    bearer_access_token = config.bearer_access_token,
    id_token_header_name = config.id_token_header_name,
    user_header_name = config.user_header_name,
    revoke_tokens_on_logout = config.revoke_tokens_on_logout,
    session_opts = getSessionOpts(config.session_opts),
    access_token_expires_leeway = config.access_token_expires_leeway,
    post_logout_redirect_uri = config.post_logout_redirect_uri,
    --Authorization properties
    enable_authorization = config.enable_authorization,
    issuers_allowed = config.issuers_allowed,
    scopes_required = config.scopes_required,
    roles_required = config.roles_required,
    realm_roles_required = config.realm_roles_required,
    client_roles_required = config.client_roles_required,
    -- Properties used to add access token claim to request header
    token_claim_header_name = "token-claim",
    token_claim_header_value = config.token_claim_header_value
  }
end

function M.exit(httpStatusCode, message, ngxCode)
  ngx.status = httpStatusCode
  ngx.say(message)
  ngx.exit(ngxCode)
end

function M.injectAccessToken(accessToken, access_token_header_name)
  ngx.req.set_header(access_token_header_name, accessToken)
end

function M.injectIDToken(idToken, id_token_header_name)
  local tokenStr = cjson.encode(idToken)
  ngx.req.set_header(id_token_header_name, ngx.encode_base64(tokenStr))
end

function M.injectUser(user, user_header_name)
  local tmp_user = user
  tmp_user.id = user.sub
  tmp_user.username = user.preferred_username
  ngx.ctx.authenticated_credential = tmp_user
  local userinfo = cjson.encode(user)
  ngx.req.set_header(user_header_name, ngx.encode_base64(userinfo))
end

function M.injectUserAttr(jwt_claims, token_claim_header_name, token_claim_header_value)
  ngx.req.set_header(token_claim_header_name, jwt_claims[token_claim_header_value])
end

function M.has_bearer_access_token()
  local header = ngx.req.get_headers()['Authorization']
  if header and header:find(" ") then
    local divider = header:find(' ')
    if string.lower(header:sub(0, divider - 1)) == string.lower("Bearer") then
      return true
    end
  end
  return false
end

function M.get_bearer_access_token()
  local header = ngx.req.get_headers()['Authorization']
  if header and header:find(" ") then
    local divider = header:find(' ')
    if string.lower(header:sub(0, divider - 1)) == string.lower("Bearer") then
      return header:sub(divider + 1)
    end
  end
  return nil
end

function M.removeAuthorizationHeader()
  ngx.req.clear_header("Authorization")
end

return M
