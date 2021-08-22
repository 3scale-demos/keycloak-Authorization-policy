local policy = require('apicast.policy')
local _M = policy.new('keycloak_Authorizer', '1.0.0')

local resty_url = require('resty.url')
local MappingRule = require('apicast.mapping_rule')
local TemplateString = require('apicast.template_string')
local default_error_message = "Request blocked due to keycloak authorization policy"
local default_template_type = 'plain'
local default_allowed_methods = { MappingRule.any_method }
local ipairs = ipairs
local new = _M.new
local resty_url = require('resty.url')

function _M.new(config)
  local self = new(config)
  self.error_message = config.error_message or default_error_message
  self.rules = {}

  --ngx.log(ngx.ERR,"issuer=",  valid_issuer_endpoint(config and config.issuer_endpoint))
  for _, rule in ipairs(config.rules) do
   
     table.insert( self.rules, {
      methods = rule.methods or default_allowed_methods,
      resource = TemplateString.new(
        rule.resource,
        rule.resource_type or default_template_type
        ),
       Keycloak_resource_name=rule.Keycloak_resource_name,
       Keycloak_scope=rule.Keycloak_scope,

    })
  end
  
   return self
end

local function isempty(s)
  return s == nil or s == ''
end

 
local function deny_request(error_msg)
  ngx.status = ngx.HTTP_FORBIDDEN
  ngx.say(error_msg)
  ngx.exit(ngx.status)
end

local function is_rule_matche_request(rule, context)

  local uri =  ngx.var.request_uri--ngx.var.uri--context:get_uri()
  local request_method =  ngx.req.get_method()

  local resource = rule.resource:render(context)
  local mapping_rule_match = false

  for _, method  in ipairs(rule.methods) do
    local mapping_rule = MappingRule.from_proxy_rule({
      http_method = method,
      pattern = resource,
      querystring_parameters = {},
      -- the name of the metric is irrelevant
      metric_system_name = 'hits'
    })
    if mapping_rule:matches(request_method, uri) then
      mapping_rule_match = true
      break
    end
  end

  ngx.log(ngx.INFO,"mapping_rule_match=",mapping_rule_match )
 
    return mapping_rule_match
 

end


local function check_keycloak_authorization(keycloak_uri,keycloak_clientID,keycloak_resource_name,keycloak_scope,token)
      local is_authorized=false
      local ops = {}
      local query={}
      local postfix="/protocol/openid-connect/token"
      local token_uri=keycloak_uri..postfix
      local httpc = require("resty.http").new()
      local res, err = httpc:request_uri(token_uri, {
        method = "POST",
        body = "grant_type=urn:ietf:params:oauth:grant-type:uma-ticket&response_mode=decision&audience="..keycloak_clientID.."&permission="..keycloak_resource_name.."#"..keycloak_scope,
        query=query,
        headers = {
            ["Content-Type"] = "application/x-www-form-urlencoded",
            ["Authorization"] = token
            
        },
      })
      if res and not isempty(res.body) then
         if  string.find(res.body, "true") then 
            is_authorized=true
        end    
      end
 
      return is_authorized
    end
    

    function _M:access(context)
        local is_kc_authorized=false
        local issuer_endpoint=context.service.oidc.issuer_endpoint
        local components = resty_url.parse(issuer_endpoint)
        local keycloak_clientID=components.user
        --TODO handle ports in keycloak url 
        local keycloack_uri=components.scheme.."://"..components.host..components.path
        local header= ngx.req.get_headers(0, true)
        local token=header["Authorization"]
         for _, rule in ipairs(self.rules) do
           if is_rule_matche_request(rule, context) then
             --return deny_request(self.error_message)
             --check keycloak authorization 
             -- if keycloack return false
             if check_keycloak_authorization(keycloack_uri,keycloak_clientID,rule.Keycloak_resource_name,rule.Keycloak_scope,token) then
                is_kc_authorized=true
                break
             end   
           end
         end
         if not is_kc_authorized then
           return deny_request(self.error_message)
         end
    end





return _M
