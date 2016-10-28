Feature: JWT Authentication

  Scenario: Request with JWT authentication using static username/password
    When I send a request 'POST' to '/tokenify/auth' with a JSON object as the body: '{"username": "operator", "password": "dobietday"}'
    Then the response has statusCode '200' and contains the object '{ "success": true }'
    And the token is not empty and is stored in JWT field
    When I send a request 'GET' to '/tokenify/jwt/session-info' with received token
    Then the response has statusCode '200' and contains the object '{"user":{"username":"operator","store":"fileEntrypointStore"}}'
    When I send a request 'GET' to '/tokenify/jwt/authorized' with received token
    Then the response has statusCode '200' and contains the object '{ "status": 200, "message": "authorized" }'
    When I send a request 'GET' to '/tokenify/jwt/authorized'
    Then the response has statusCode '403' and contains the object '{ "success": false }'

  Scenario: Request with JWT authentication using valid username/password from REST API
    Given a mock rest server provides method 'POST' on path '/auth' with the mapping
      | requestBody | responseCode | responseBody |
      | { "realm": "mycompany", "username": "apiuser", "password": "dobietday" } | 200 | {"status": 0, "permissions": ["perm1", "perm2"], "settings": {"key1": "value1", "key2": "value2"}} |
    When I send a request 'POST' to '/tokenify/auth' with a JSON object as the body: '{"realm":"mycompany", "username": "apiuser", "password": "dobietday"}'
    Then the response has statusCode '200' and contains the object '{ "success": true }'
    And the token is not empty and is stored in JWT field
    When I send a request 'GET' to '/tokenify/jwt/session-info' with received token
    Then the response has statusCode '200' and contains the object '{"user":{"realm":"mycompany","username":"apiuser","store":"restEntrypointStore", "permissions":["perm1","perm2"], "settings": {"key1": "value1", "key2": "value2"}}}'
