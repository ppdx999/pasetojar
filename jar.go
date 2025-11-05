// Package pasetojar provides a thin wrapper for secure cookie management using PASETO v4.local tokens.
//
// This package offers a simple interface for storing encrypted data in HTTP cookies,
// leveraging the security of PASETO (Platform-Agnostic Security Tokens) for encryption
// and automatic expiration validation.
//
// Basic usage:
//
//	key := paseto.NewV4SymmetricKey()
//	params := pasetojar.CookieParams{
//		Path:     "/",
//		MaxAge:   24 * time.Hour,
//		Secure:   true,
//		HttpOnly: true,
//		SameSite: http.SameSiteStrictMode,
//	}
//	jar, err := pasetojar.New("session", key, params)
//	if err != nil {
//		// Handle error (e.g., invalid MaxAge)
//	}
//
//	// Set a cookie
//	session := map[string]interface{}{"user_id": 42, "role": "admin"}
//	jar.Set(w, session)
//
//	// Get a cookie
//	var data map[string]interface{}
//	if err := jar.Get(r, &data); err != nil {
//		if errors.Is(err, pasetojar.ErrCookieNotFound) {
//			// Handle missing cookie
//		}
//	}
//
//	// Clear a cookie
//	jar.Clear(w)
package pasetojar

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	paseto "aidanwoods.dev/go-paseto"
)

var (
	// ErrCookieNotFound is returned when the requested cookie is not present in the request.
	ErrCookieNotFound = errors.New("cookie not found")
	// ErrInvalidToken is returned when the token is invalid, expired, or tampered with.
	ErrInvalidToken = errors.New("invalid or expired token")
	// ErrInvalidMaxAge is returned when MaxAge is not greater than 0.
	ErrInvalidMaxAge = errors.New("MaxAge must be greater than 0")
)

// Jar handles encrypted cookie storage using PASETO v4.local tokens.
// It provides methods to securely set, get, and clear cookies with automatic
// encryption, decryption, and expiration validation.
//
// All data stored in cookies is encrypted using PASETO v4.local, which provides
// authenticated encryption. The encrypted tokens include timestamps and are
// automatically validated for expiration when retrieved.
type Jar struct {
	name   string
	key    paseto.V4SymmetricKey
	params CookieParams
}

// CookieParams contains HTTP cookie configuration parameters.
//
// Note: MaxAge must be greater than 0. Session cookies are not supported
// as encrypted session cookies have limited practical use cases.
//
// For security best practices, it's recommended to set:
//   - Secure: true (require HTTPS)
//   - HttpOnly: true (prevent JavaScript access)
//   - SameSite: http.SameSiteStrictMode or http.SameSiteLaxMode
type CookieParams struct {
	// Path specifies the cookie path. Use "/" for the entire domain.
	Path string
	// Domain specifies the cookie domain. Empty string means current domain only.
	Domain string
	// MaxAge specifies cookie lifetime. Must be greater than 0.
	MaxAge time.Duration
	// Secure requires HTTPS. Should be true in production.
	Secure bool
	// HttpOnly prevents JavaScript access. Should be true for sensitive cookies.
	HttpOnly bool
	// SameSite controls cross-site request behavior.
	SameSite http.SameSite
}

// New creates a new Jar instance for managing encrypted cookies.
//
// Returns ErrInvalidMaxAge if params.MaxAge is not greater than 0.
//
// Parameters:
//   - name: The cookie name that will be used in HTTP headers
//   - key: A PASETO v4 symmetric key for encryption/decryption (generate with paseto.NewV4SymmetricKey())
//   - params: Cookie configuration parameters (path, domain, security settings, etc.)
//
// Example:
//
//	key := paseto.NewV4SymmetricKey()
//	params := pasetojar.CookieParams{
//		Path:     "/",
//		MaxAge:   24 * time.Hour,
//		Secure:   true,
//		HttpOnly: true,
//		SameSite: http.SameSiteStrictMode,
//	}
//	jar, err := pasetojar.New("session", key, params)
//	if err != nil {
//		// Handle error
//	}
func New(name string, key paseto.V4SymmetricKey, params CookieParams) (*Jar, error) {
	if params.MaxAge <= 0 {
		return nil, ErrInvalidMaxAge
	}
	return &Jar{
		name:   name,
		key:    key,
		params: params,
	}, nil
}

// Name returns the cookie name used by this Jar.
func (j *Jar) Name() string {
	return j.name
}

// Key returns the PASETO v4 symmetric key used for encryption and decryption.
func (j *Jar) Key() paseto.V4SymmetricKey {
	return j.key
}

// Params returns a copy of the cookie parameters used by this Jar.
func (j *Jar) Params() CookieParams {
	return j.params
}

// Get retrieves and decrypts the cookie value from the HTTP request.
//
// The encrypted token is automatically validated for:
//   - Cryptographic authenticity (prevents tampering)
//   - Expiration time (if MaxAge was set)
//
// Parameters:
//   - r: The HTTP request containing the cookie
//   - out: Pointer to a variable where the decrypted data will be stored
//
// Returns:
//   - ErrCookieNotFound: If the cookie is not present in the request
//   - ErrInvalidToken: If the token is invalid, expired, or tampered with
//   - Other errors: For unexpected failures
//
// Example:
//
//	var session Session
//	err := jar.Get(r, &session)
//	if errors.Is(err, pasetojar.ErrCookieNotFound) {
//		// User is not logged in
//	} else if errors.Is(err, pasetojar.ErrInvalidToken) {
//		// Token expired or tampered with - require re-authentication
//	} else if err != nil {
//		// Handle other errors
//	}
func (j *Jar) Get(r *http.Request, out any) error {
	c, err := r.Cookie(j.name)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return ErrCookieNotFound
		}
		return err
	}

	parser := paseto.NewParser()
	parser.AddRule(paseto.NotExpired())

	tok, err := parser.ParseV4Local(j.key, c.Value, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if err := tok.Get("data", out); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	return nil
}


// Set encrypts the given value and stores it as a cookie in the HTTP response.
//
// The value is encrypted using PASETO v4.local and includes:
//   - Issued-at timestamp
//   - Expiration time (based on MaxAge)
//   - The provided data in the "data" claim
//
// The cookie will expire after the duration specified in MaxAge.
//
// Parameters:
//   - w: The HTTP response writer where the cookie will be set
//   - v: The value to encrypt and store (must be serializable to JSON)
//
// Returns:
//   - error: Returns an error if encryption or serialization fails
//
// Example:
//
//	session := Session{UserID: 42, Role: "admin"}
//	if err := jar.Set(w, session); err != nil {
//		// Handle error
//	}
func (j *Jar) Set(w http.ResponseWriter, v any) error {
	tok := paseto.NewToken()
	now := time.Now()
	tok.SetIssuedAt(now)
	tok.SetExpiration(now.Add(j.params.MaxAge))
	tok.Set("data", v)

	c := &http.Cookie{
		Name:     j.name,
		Value:    tok.V4Encrypt(j.key, nil),
		Path:     j.params.Path,
		Domain:   j.params.Domain,
		MaxAge:   int(j.params.MaxAge / time.Second),
		Expires:  now.Add(j.params.MaxAge),
		HttpOnly: j.params.HttpOnly,
		Secure:   j.params.Secure,
		SameSite: j.params.SameSite,
	}
	http.SetCookie(w, c)
	return nil
}

// Clear removes the cookie by setting it to expire immediately.
//
// This method sets the cookie's MaxAge to -1 and Expires to a past date,
// instructing the browser to delete the cookie. All other cookie parameters
// (Path, Domain, Secure, HttpOnly, SameSite) are preserved to ensure the
// cookie is properly matched and deleted.
//
// Parameters:
//   - w: The HTTP response writer where the cookie deletion will be set
//
// Example:
//
//	// Log out user by clearing session cookie
//	jar.Clear(w)
func (j *Jar) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     j.name,
		Value:    "",
		Path:     j.params.Path,
		Domain:   j.params.Domain,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: j.params.HttpOnly,
		Secure:   j.params.Secure,
		SameSite: j.params.SameSite,
	})
}

