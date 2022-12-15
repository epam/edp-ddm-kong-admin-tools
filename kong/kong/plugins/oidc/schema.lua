local typedefs = require "kong.db.schema.typedefs"

return {
  name = "oidc",
  fields = {
    { consumer = typedefs.no_consumer },
    { config = {
      type = "record",
      fields = {
        { anonymous = { type = "string", uuid = true }, },
        { client_id = { type = "string", required = true }, },
        { client_secret = { type = "string", required = true }, },
        { discovery = { type = "string", required = true, default = "https://.well-known/openid-configuration" }, },
        { introspection_endpoint = { type = "string", required = false }, },
        { allow_token_auth = {type = "boolean", required = false, default = false}, },
        { timeout = { type = "number", required = false }, },
        { introspection_endpoint_auth_method = { type = "string", required = false }, },
        { bearer_only = { type = "string", required = true, default = "no" }, },
        { realm = { type = "string", required = true, default = "kong" }, },
        { redirect_uri_path = { type = "string" }, },
        --redirect_uri = { type = "string" },
        { scope = { type = "string", required = true, default = "openid" }, },
        { response_type = { type = "string", required = true, default = "code" }, },
        { ssl_verify = { type = "string", required = true, default = "no" }, },
        { token_endpoint_auth_method = { type = "string", required = true, default = "client_secret_post" }, },
        { recovery_page_path = { type = "string" }, },
        { logout_path = { type = "string", required = false, default = '/logout' }, },
        { redirect_after_logout_uri = { type = "string", required = false }, },
        { filters = { type = "string" }, },
        { unauth_action = { type = "string", required = true, default = "deny" }, },
        { access_token_header_name = { type = "string", required = true, default = "X-Access-Token" }, },
        { bearer_access_token = { type = "string", required = true, default = "no" }, },
        { id_token_header_name = { type = "string", required = true, default = "X-ID-Token" }, },
        { user_header_name = { type = "string", required = true, default = "X-Userinfo" }, },
        { revoke_tokens_on_logout = {type = "boolean", required = false, default = false}, },
        { session_opts = { type = "string"}, },
        { access_token_expires_leeway = { type = "number", required = false }, },
        { post_logout_redirect_uri = { type = "string", required = false}, },
        -- Authorisation properties
        { enable_authorization = {type = "boolean", required = false, default = true}, },
        { issuers_allowed = { type = "array", elements = { type = "string" }, required = false }, },
        { scopes_required = { type = "array", elements = { type = "string" }, default = nil }, },
        { roles_required = { type = "array", elements = { type = "string" }, default = nil }, },
        { realm_roles_required = { type = "array", elements = { type = "string" }, default = nil }, },
        { client_roles_required = { type = "array", elements = { type = "string" }, default = nil }, },
        -- Property used to add access token claim value to request header
        { token_claim_header_value = { type = "string", required = false } }
      },
    },
    },
  },
}
