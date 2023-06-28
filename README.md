
## 3scale Keycloak Authorization Policy

This Policy integrates APICast (3scale API Gateway) with  [Keycloak Authorization services](https://www.keycloak.org/docs/latest/authorization_services/)  ,allows APICast to enforce authorization decisions (determine if access to an API should be granted or denied)  based on the defined policies in keycloak authorization services.

Keycloak provides fine grained authorization policies  through multiple patterns (ABAC/RBAC/UBAC/time-based).For more information about Keycloak Authorization service please check the [documentation](https://www.keycloak.org/docs/latest/authorization_services/)

## How it works?

- The policy intercepts the client request filtering that matches with the configured mapping rules and methods of the defined resource. 
- When a mapping rule matches the client request , the policy will send an authorization request to the token endpoint passing the requested resource name and scope for obtaining a permission from keycloak server.
 - Keycloak will evaluate all policies associated with the resource and scope being requested responding with the decesion .
 - The pollicy will allow/deny the client request based on the reponse of the keycloak authorization services.
 
 
## How to use it?
 
 - Deploy the custom policy in your 3scale environment.
 - create an OpenID Connect client in Keycloak.
 - Enable Authorization service in the client by Settting Authorization Enabled to On.
 - Create Resource,Scope,Policy,permission in Keycloak.
 - configure OpenID Connect authentication method in 3scale product.
 - Add the policy to the chain after APICast default policy.
 - Add one or more mapping rules of the resources to be protected with the defined keycloak resource name and scope as below screenshot.

![alt text](https://github.com/abdelhamidfg/keycloak-Authorization-policy/blob/master/Authorizer-rule.jpg?raw=true)


## Policy Installation on OpenShift using 3scale APIcast self-managed

  
1. Install the APIcast operator as described in the [documentation](https://github.com/3scale/apicast-operator/blob/master/doc/quickstart-guide.md#Install-the-APIcast-operator)
2. Create a Kubernetes secret that contains a 3scale Porta admin portal endpoint information
```shell
oc create secret generic 3scaleportal --from-literal=AdminPortalURL=https://access-token@account-admin.3scale.net
```
3. create a secret containing the policy Lua files (the files exist in the  folder /policies/keycloak_Authorizer/1.0.0)
```shell
oc create secret generic keycloak_authorizer-policy   --from-file=keycloak_Authorizer.lua   --from-file=init.lua --from-file=apicast-policy.json  --from-file=http_headers.lua --from-file=http_connect.lua 
```
4.Create APIcast custom resource instance
```shell
apiVersion: apps.3scale.net/v1alpha1
kind: APIcast
metadata:
  name: apicast-kca
spec: 
  adminPortalCredentialsRef:
    name: 3scaleportal
  replicas: 1  
  customPolicies:
    - name: keycloak_authorizer
      secretRef:
        name: keycloak_authorizer-policy
      version: 1.0.0
```
5. Create 3scale API Manager CustomPolicyDefinition Custom Resource 
 in order to view the policy configuration in the API Manager policy editor UI, the custom policy should be registered using customPolicyDefinition custom resource
```shell
apiVersion: capabilities.3scale.net/v1beta1
kind: CustomPolicyDefinition
metadata:
 name: custompolicydefinition-kca
spec:
 name: "keycloak_authorizer"
 version: "1.0.0"
 schema:
    $schema: 'http://json-schema.org/draft-07/schema#'
    configuration:
      properties:
        error_message:
          description: Error message to show to user when traffic is blocked
          title: Error message
          type: string
        rules:
          description: 'List of rules '
          items:
            properties:
              Keycloak_resource_name:
                description: Keycloak resource name
                type: string
              Keycloak_scope:
                description: Keycloak scope name
                type: string
              methods:
                default:
                  - ANY
                description: Allowed methods
                items:
                  enum:
                    - ANY
                    - GET
                    - HEAD
                    - POST
                    - PUT
                    - DELETE
                    - PATCH
                    - OPTIONS
                    - TRACE
                    - CONNECT
                  type: string
                type: array
              resource:
                description: >-
                  Resource controlled by the rule. This is the same format as
                  Mapping Rules. This matches from the beginning of the string
                  and to make an exact match you need to use '$' at the end.
                type: string
              resource_type:
                description: How to evaluate 'resource' field
                oneOf:
                  - enum:
                      - plain
                    title: Evaluate as plain text.
                  - enum:
                      - liquid
                    title: Evaluate as liquid.
                type: string
            required:
              - Keycloak_resource_name
              - resource
              - Keycloak_scope
            type: object
          type: array
      type: object
    name: keycloak_authorizer
    summary: 'The policy checks for valid credentials in the Authorization header '
    version: 1.0.0
```  
