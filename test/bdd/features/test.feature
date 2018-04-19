Feature: JWT Authentication

  Scenario: Request with JWT authentication using static username/password
    When I send a request 'POST' to '/tokenify/auth' with a JSON object as the body: '{"username": "operator", "password": "dobietday"}'
    Then the response has statusCode '200' and contains the object '{ "success": true }'
    And the token is not empty and is stored in JWT field
    When I send a request 'GET' to '/tokenify/jwt/session-info' with received token
    Then the response has statusCode '200' and contains the object '{"user":{"username":"operator","store":"fileEntrypointStore"}}'
