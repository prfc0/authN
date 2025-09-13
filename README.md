# Authentication Demo (Go)

A simple authentication service demo built in Go, using JWT and refresh tokens.

## Run the Server

```bash
$ go run ./cmd/server/main.go
backend running on :8080
````

## Test the API Endpoints

### Register

```bash
$ curl \
    -X POST \
    -H "Content-Type: application/json" \
    http://localhost:8080/api/v1/auth/register \
    -d '{"username":"someuser","password":"somepass"}'

{
  "user_id": 2,
  "username": "someuser"
}
```

### Login

```bash
$ curl \
    -X POST \
    -H "Content-Type: application/json" \
    http://localhost:8080/api/v1/auth/login \
    -d '{"username":"someuser","password":"somepass"}'

{
  "user_id": 2,
  "access_token": "<ACCESS_TOKEN>",
  "access_expires_in": 900,
  "refresh_token": "<REFRESH_TOKEN>",
  "refresh_expires_in": 86400
}
```

### Call Backend Service (Authorized)

```bash
$ curl -H "Authorization: Bearer <ACCESS_TOKEN>" \
    http://localhost:8080/api/v1/backend

{
  "message": "Hello someuser, from backend!"
}
```

### Refresh Token

```bash
$ curl \
    -X POST \
    -H "Content-Type: application/json" \
    http://localhost:8080/api/v1/auth/refresh \
    -d '{"refresh_token":"<REFRESH_TOKEN>"}'

{
  "user_id": 2,
  "access_token": "<NEW_ACCESS_TOKEN>",
  "access_expires_in": 900,
  "refresh_token": "<NEW_REFRESH_TOKEN>",
  "refresh_expires_in": 86400
}
```

### No Token Provided

```bash
$ curl \
    http://localhost:8080/api/v1/backend

{
  "error": "authorization_required"
}
```

### Invalid Token

```bash
$ curl \
    -H "Authorization: Bearer foo" \
    http://localhost:8080/api/v1/backend

{
  "error": "invalid_token"
}
```

## Acknowledgments

This project was developed with help from the OpenAI ChatGPT-5 model.
