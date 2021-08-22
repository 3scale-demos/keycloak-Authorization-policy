
## 3scale Keycloak Authorization Policy

This Policy integrates APICast (3scale API Gateway) with  [Keycloak Authorization services](https://www.keycloak.org/docs/latest/authorization_services/)  ,allows APICast to enforce authorization decisions (determine if access to an API should be granted or denied)  based on the defined policies in keycloak authorization services.

Keycloak provides fine grained authorization policies  through multiple patterns (ABAC/RBAC/UBAC/time-based).For more information about Keycloak Authorization service please check the [documentation](https://www.keycloak.org/docs/latest/authorization_services/)

## How it works?

- The policy intercepts the client request filtering that matches with the configured mapping rules and methods of the defined resource. 
- When a mapping rule matches the client request , the policy will send an authorization request to the token endpoint passing the requested resource name and scope for obtaining a permission from keycloak server.
 - Keycloak will evaluate all policies associated with the resource and scope being requested responding with the decesion .
 - The pollicy will allow/deny the client request based on the reponse of the keycloak authorization services.
 
 
## How to use it?
 
 - Deploy the custom policy in your 3scale enviroment.
 - create an OpenID Connect client in Keycloak.
 - Enable Authorization service in the client by Settting Authorization Enabled to On.
 - Create Resource,Scope,Policy,permission in Keycloak.
 - configure OpenID Connect authentication method in 3scale product.
 - Add the policy to the chain after APICast default policy.
 - Add one or more mapping rules of the resources to be protected with the defined keycloak resource name and scope as below screenshot.

![alt text](https://github.com/abdelhamidfg/keycloak-Authorization-policy/blob/master/Authorizer-rule.jpg?raw=true)
