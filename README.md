# pasetojar

[![Go Reference](https://pkg.go.dev/badge/github.com/ppdx999/pasetojar.svg)](https://pkg.go.dev/github.com/ppdx999/pasetojar)
[![Go Report Card](https://goreportcard.com/badge/github.com/ppdx999/pasetojar)](https://goreportcard.com/report/github.com/ppdx999/pasetojar)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Minimal and idiomatic Go package for handling encrypted cookie sessions using PASETO (v4.local).

## Features

- 🔒 **Secure**: Uses PASETO v4.local for authenticated encryption
- 🎯 **Simple**: Clean API with just three methods: `Set`, `Get`, and `Clear`
- 📦 **Minimal dependencies**: Only depends on `aidanwoods.dev/go-paseto`

## Installation

```bash
go get github.com/ppdx999/pasetojar
```

## Quick Start

```go
package main

import (
    "errors"
    "net/http"
    "time"

    paseto "aidanwoods.dev/go-paseto"
    "github.com/ppdx999/pasetojar"
)

type Session struct {
    UserID int64  `json:"user_id"`
    Role   string `json:"role"`
}

func main() {
    // Generate a symmetric key (store this securely!)
    key := paseto.NewV4SymmetricKey()

    // Configure cookie parameters
    params := pasetojar.CookieParams{
        Path:     "/",
        Domain:   "",
        MaxAge:   24 * time.Hour,
        Secure:   true,
        HttpOnly: true,
        SameSite: http.SameSiteStrictMode,
    }

    // Create a jar instance
    jar, err := pasetojar.New("session", key, params)
    if err != nil {
        panic(err)
    }

    // Set a cookie
    http.HandleFunc("/set-cookie", func(w http.ResponseWriter, r *http.Request) {
        session := Session{UserID: 42, Role: "admin"}
        if err := jar.Set(w, session); err != nil {
            http.Error(w, "Failed to set cookie", http.StatusInternalServerError)
            return
        }
        w.Write([]byte("Cookie set!"))
    })

    // Get a cookie
    http.HandleFunc("/get-cookie", func(w http.ResponseWriter, r *http.Request) {
        var session Session
        err := jar.Get(r, &session)
        if errors.Is(err, pasetojar.ErrCookieNotFound) {
            http.Error(w, "Not logged in", http.StatusUnauthorized)
            return
        } else if errors.Is(err, pasetojar.ErrInvalidToken) {
            http.Error(w, "Invalid or expired session", http.StatusUnauthorized)
            return
        } else if err != nil {
            http.Error(w, "Internal error", http.StatusInternalServerError)
            return
        }
        w.Write([]byte("Retrieved session for user ID: " + string(session.UserID)))
    })

    // Clear a cookie
    http.HandleFunc("/clear-cookie", func(w http.ResponseWriter, r *http.Request) {
        jar.Clear(w)
        w.Write([]byte("Cookie cleared!"))
    })

    http.ListenAndServe(":8080", nil)
}
```

## API Reference

### Creating a Jar

```go
jar, err := pasetojar.New(name string, key paseto.V4SymmetricKey, params CookieParams) (*Jar, error)
```

Creates a new Jar instance. Returns `ErrInvalidMaxAge` if `params.MaxAge <= 0`.

**Note**: Session cookies (MaxAge=0) are not supported. All cookies must have a positive MaxAge.

### Setting a Cookie

```go
err := jar.Set(w http.ResponseWriter, v any) error
```

Encrypts and stores a value in a cookie. The value must be JSON-serializable.

### Getting a Cookie

```go
err := jar.Get(r *http.Request, out any) error
```

Retrieves and decrypts a cookie value. Returns:
- `ErrCookieNotFound` if the cookie doesn't exist
- `ErrInvalidToken` if the token is invalid, expired, or tampered with

### Clearing a Cookie

```go
jar.Clear(w http.ResponseWriter)
```

Deletes the cookie by setting it to expire immediately.

### Getters

```go
jar.Name() string                     // Returns the cookie name
jar.Key() paseto.V4SymmetricKey       // Returns the encryption key
jar.Params() CookieParams             // Returns the cookie parameters
```

## Security Best Practices

1. **Generate and store keys securely**:
   ```go
   // Generate once and store in environment variable or secrets manager
   key := paseto.NewV4SymmetricKey()
   ```

2. **Use secure cookie settings in production**:
   ```go
   params := pasetojar.CookieParams{
       Path:     "/",
       MaxAge:   24 * time.Hour,
       Secure:   true,  // Require HTTPS
       HttpOnly: true,  // Prevent JavaScript access
       SameSite: http.SameSiteStrictMode,  // CSRF protection
   }
   ```

3. **Handle errors appropriately**:
   ```go
   if errors.Is(err, pasetojar.ErrCookieNotFound) {
       // User is not logged in
   } else if errors.Is(err, pasetojar.ErrInvalidToken) {
       // Session expired or tampered with - require re-authentication
   }
   ```

## Why PASETO?

[PASETO](https://paseto.io/) (Platform-Agnostic Security Tokens) provides:
- **Simplicity**: No algorithm negotiation, one secure default
- **Security**: Authenticated encryption prevents tampering
- **Modern cryptography**: Uses proven, modern algorithms
- **No footguns**: Designed to prevent common JWT mistakes

## Comparison with JWT

| Feature | PASETO | JWT |
|---------|--------|-----|
| Algorithm selection | One secure default | Multiple algorithms (risky) |
| Encryption | Built-in | Optional (JWE is complex) |
| Tampering protection | Always authenticated | Depends on algorithm |
| Complexity | Low | High |

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built on top of [aidanwoods.dev/go-paseto](https://github.com/aidanwoods/go-paseto)
