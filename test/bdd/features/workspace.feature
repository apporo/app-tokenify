Feature: Temporary workspace

  Scenario: Request with basic authentication using static username/password
    When I send a request to '/tokenify/httpauth/authorized' with username 'invaliduser' and password 'secretpassword' in 'basic' mode
    Then the response has statusCode '401' and contains the object '{ }'
    When I send a request to '/tokenify/httpauth/authorized' with username 'Authuser' and password 'secretpassword' in 'basic' mode
    Then the response has statusCode '200' and contains the object '{ "status": 200, "message": "authorized" }'
