local BasePlugin = require "kong.plugins.base_plugin"
local OidcHandler = BasePlugin:extend()
local utils = require("kong.plugins.oidc.utils")
local filter = require("kong.plugins.oidc.filter")
local session = require("kong.plugins.oidc.session")
local cjson = require("cjson")
local jwt_decoder = require("kong.plugins.jwt.jwt_parser")

OidcHandler.PRIORITY = 1000

function OidcHandler:new()
  OidcHandler.super.new(self, "oidc")
end

function OidcHandler:access(config)
  OidcHandler.super.access(self)
  local oidcConfig = utils.get_options(config, ngx)

  if filter.shouldProcessRequest(oidcConfig) then
    session.configure(config)
    handle(oidcConfig)
  else
    ngx.log(ngx.DEBUG, "OidcHandler ignoring request, path: " .. ngx.var.request_uri)
  end

  ngx.log(ngx.DEBUG, "OidcHandler done")
end

local function validate_issuer(allowed_issuers, jwt_claims)
  if allowed_issuers == nil or table.getn(allowed_issuers) == 0 then
    return nil, "Allowed issuers is empty. Please add at least one."
  end
  if jwt_claims.iss == nil then
    ngx.log(ngx.WARN, "Missing issuer claim in JWT. sub: " .. jwt_claims.sub)
    return nil, "Missing issuer claim in JWT"
  end
  for _, curr_iss in pairs(allowed_issuers) do
    if curr_iss == jwt_claims.iss or string.match(jwt_claims.iss, curr_iss) ~= nil then
      return true
    end
  end
  ngx.log(ngx.WARN, "Token issuer not allowed: " .. jwt_claims.iss .. " sub: " .. jwt_claims.sub)
  return nil, "Token issuer not allowed"
end

local function validate_client_roles(allowed_client_roles, jwt_claims)
  if allowed_client_roles == nil or table.getn(allowed_client_roles) == 0 then
    return true
  end

  if jwt_claims == nil or jwt_claims.resource_access == nil then
    return nil, "Missing required resource_access claim"
  end

  for _, allowed_client_role in pairs(allowed_client_roles) do
    for curr_allowed_client, curr_allowed_role in string.gmatch(allowed_client_role, "(%S+):(%S+)") do
      for claim_client, claim_client_roles in pairs(jwt_claims.resource_access) do
        if curr_allowed_client == claim_client then
          for _, curr_claim_client_roles in pairs(claim_client_roles) do
            for _, curr_claim_client_role in pairs(curr_claim_client_roles) do
              if curr_claim_client_role == curr_allowed_role then
                return true
              end
            end
          end
        end
      end
    end
  end

  return nil, "Missing required role"
end

local function validate_roles(allowed_roles, jwt_claims)
  if allowed_roles == nil or table.getn(allowed_roles) == 0 then
    return true
  end

  if jwt_claims.azp == nil then
    return nil, "Missing required azp claim"
  end

  local tmp_allowed = {}
  for i, allowed in pairs(allowed_roles) do
    tmp_allowed[i] = jwt_claims.azp .. ":" .. allowed
  end

  return validate_client_roles(tmp_allowed, jwt_claims)
end

local function validate_realm_roles(allowed_realm_roles, jwt_claims)
  if allowed_realm_roles == nil or table.getn(allowed_realm_roles) == 0 then
    return true
  end

  if jwt_claims == nil or jwt_claims.realm_access == nil or jwt_claims.realm_access.roles == nil then
    return nil, "Missing required realm_access.roles claim"
  end

  for _, curr_claim_role in pairs(jwt_claims.realm_access.roles) do
    for _, curr_allowed_role in pairs(allowed_realm_roles) do
      if curr_claim_role == curr_allowed_role then
        return true
      end
    end
  end

  return nil, "Missing required realm role"
end

local function validate_scope(allowed_scopes, jwt_claims)
  if allowed_scopes == nil or table.getn(allowed_scopes) == 0 then
    return true
  end

  if jwt_claims == nil or jwt_claims.scope == nil then
    return nil, "Missing required scope claim"
  end

  for scope in string.gmatch(jwt_claims.scope, "%S+") do
    for _, curr_scope in pairs(allowed_scopes) do
      if scope == curr_scope then
        return true
      end
    end
  end
  return nil, "Missing required scope"
end

local function authorize(oidcConfig, jwt)
  if not jwt then
    return false, { status = ngx.HTTP_UNAUTHORIZED, message = "Access token is missing or invalid" }
  end

  -- Verify that the issuer is allowed
  local isAllowed, err = validate_issuer(oidcConfig.issuers_allowed, jwt.claims)
  if not isAllowed then
    return false, { status = ngx.HTTP_UNAUTHORIZED, message = err }
  end

  -- Verify roles or scopes
  local ok, err = validate_scope(oidcConfig.scopes_required, jwt.claims)

  if ok then
    ok, err = validate_realm_roles(oidcConfig.realm_roles_required, jwt.claims)
  end

  if ok then
    ok, err = validate_roles(oidcConfig.roles_required, jwt.claims)
  end

  if ok then
    ok, err = validate_client_roles(oidcConfig.client_roles_required, jwt.claims)
  end

  if ok then
    --kong.ctx.shared.jwt_keycloak_token = jwt
    return true
  end

  local errMsg = "Access token does not have the required scope/role: " .. err
  ngx.log(ngx.WARN, errMsg .. " sub: " .. jwt.claims.sub)
  return false, { status = ngx.HTTP_FORBIDDEN, message = errMsg }

end

local function introspect(oidcConfig)
  ngx.log(ngx.DEBUG, "Starting token introspection, requested path: " .. ngx.var.request_uri)
  if (utils.has_bearer_access_token() or oidcConfig.bearer_only == "yes") then
    local res, err = require("resty.openidc").introspect(oidcConfig)
    if err then
      if oidcConfig.bearer_only == "yes" then
        ngx.header["WWW-Authenticate"] = 'Bearer realm="' .. oidcConfig.realm .. '",error="' .. err .. '"'
        ngx.log(ngx.INFO, "Error while token introspection, requested path: " .. ngx.var.request_uri .. " Error: " .. err)
        utils.exit(ngx.HTTP_UNAUTHORIZED, err, ngx.HTTP_UNAUTHORIZED)
      end
      return nil
    end
    return res
  end
  return nil
end

local function make_oidc(oidcConfig)
  ngx.log(ngx.DEBUG, "OidcHandler calling authenticate, requested path: " .. ngx.var.request_uri)
  local res, err, target_url = require("resty.openidc").authenticate(oidcConfig, nil, oidcConfig.unauth_action, oidcConfig.session_opts)
  if err then
    ngx.log(ngx.DEBUG, "OidcHandler error: " .. err)
    if err == "unauthorized request" then
      ngx.log(ngx.INFO, "OidcHandler unauthorized request to " .. target_url)
      utils.exit(ngx.HTTP_UNAUTHORIZED, err, ngx.HTTP_UNAUTHORIZED)
    end
    if oidcConfig.recovery_page_path then
      ngx.log(ngx.DEBUG, "Entering recovery page: " .. oidcConfig.recovery_page_path)
      ngx.redirect(oidcConfig.recovery_page_path)
    end
	  ngx.log(ngx.DEBUG, "Error while requesting " .. ngx.var.request_uri)
    utils.exit(500, err, ngx.HTTP_INTERNAL_SERVER_ERROR)
  end
  return res
end

function handle(oidcConfig)
  local response
  local userToken
  local accessToken
  local idToken

  -- If there is a bearer token than introspect it
  if oidcConfig.allow_token_auth and oidcConfig.introspection_endpoint then
    userToken = introspect(oidcConfig)
    if userToken then
      ngx.log(ngx.DEBUG, "OidcHandler introspect succeeded, requested path: " .. ngx.var.request_uri .. " User ID: " .. userToken.sub)
      accessToken = utils.get_bearer_access_token()
      -- remove Authorization header with bearer token as we will inject it into custom header
      utils.removeAuthorizationHeader()
    end
  end

  if userToken == nil then
    -- No bearer token in request, trying OIDC
    response = make_oidc(oidcConfig)
    if response then
      userToken = response.user
      accessToken = response.access_token
      idToken = response.id_token
    end
  end

  -- Decode access token
  local jwt, jwtErr
  if accessToken then
    jwt, jwtErr = jwt_decoder:new(accessToken)
    if jwtErr then
      ngx.log(ngx.DEBUG, "Failed to parse access token: " .. jwtErr)
    end
  end

 -- Perform authorization
  if oidcConfig.enable_authorization and jwt then
    ngx.log(ngx.DEBUG, "Authorizing request: " .. ngx.var.request_uri)

    --Authorize access
    local ok, err = authorize(oidcConfig, jwt)
    if not ok then
      ngx.log(ngx.WARN, "Authorization failed: " .. err.message .. " Request URI: " .. ngx.var.request_uri)
      utils.exit(err.status, "", err.status)
    end
  end

  -- Add headers
  if (userToken) then
    --Inject user token as header
    utils.injectUser(userToken, oidcConfig.user_header_name)
  end
  if (accessToken) then
    --Inject access token as header
    if (oidcConfig.bearer_access_token == "yes") then
        utils.injectAccessToken("Bearer " .. accessToken, "Authorization")
    else
      utils.injectAccessToken(accessToken, oidcConfig.access_token_header_name)
    end
    -- Inject token claim value as a header (can be used for rate-limiting)
    if oidcConfig.token_claim_header_name ~= nil and oidcConfig.token_claim_header_name ~= '' and oidcConfig.token_claim_header_value ~= nil and oidcConfig.token_claim_header_value ~= '' then
      if jwt and jwt.claims ~= nil then
        utils.injectUserAttr(jwt.claims, oidcConfig.token_claim_header_name, oidcConfig.token_claim_header_value)
      else
        ngx.log(ngx.WARN, "Can't inject '" .. oidcConfig.token_claim_header_name .. "' header with '" .. oidcConfig.token_claim_header_value .. "' claim value from access token as token is missing or invalid")
      end
    end
  end
  if (idToken) then
    utils.injectIDToken(idToken, oidcConfig.id_token_header_name)
  end
  --end
end

return OidcHandler
