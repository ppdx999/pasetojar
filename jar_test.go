package pasetojar_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	paseto "aidanwoods.dev/go-paseto"
	"github.com/ppdx999/pasetojar"
)

type Session struct {
	UID  int64  `json:"uid"`
	Role string `json:"role"`
	Name string `json:"name"`
}

func eqSessions(a, b Session) bool {
	return a.UID == b.UID && a.Role == b.Role && a.Name == b.Name
}

func defaultParams() pasetojar.CookieParams {
	return pasetojar.CookieParams{
		Path:     "/",
		Domain:   "",
		MaxAge:   2 * time.Hour,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

func cookieFromRecorder(w *httptest.ResponseRecorder, name string) (*http.Cookie, bool) {
	for _, h := range w.Result().Cookies() {
		if h.Name == name {
			return h, true
		}
	}
	return nil, false
}

func reqWithCookie(c *http.Cookie) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.AddCookie(c)
	return req
}

func TestSetAndGet_RoundTrip(t *testing.T) {
	jar, err := pasetojar.New("session", paseto.NewV4SymmetricKey(), defaultParams())
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	w := httptest.NewRecorder()
	in := Session{UID: 42, Role: "admin", Name: "Bob"}
	if err := jar.Set(w, in); err != nil {
		t.Fatalf("Set error: %v", err)
	}
	c, ok := cookieFromRecorder(w, "session")
	if !ok {
		t.Fatal("cookie not set")
	}

	var out Session
	if err := jar.Get(reqWithCookie(c), &out); err != nil {
		t.Fatalf("Get error: %v", err)
	}
	if !eqSessions(in, out) {
		t.Fatalf("got different session: want %+v, got %+v", in, out)
	}
}

func TestGet_CookieNotFound(t *testing.T) {
	jar, err := pasetojar.New("session", paseto.NewV4SymmetricKey(), defaultParams())
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)

	var out Session
	err = jar.Get(req, &out)
	if !errors.Is(err, pasetojar.ErrCookieNotFound) {
		t.Errorf("expected ErrCookieNotFound, got %v", err)
	}
}

func TestGet_InvalidToken(t *testing.T) {
	jar, err := pasetojar.New("session", paseto.NewV4SymmetricKey(), defaultParams())
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	// Create a cookie with invalid token value
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "session",
		Value: "invalid-token-data",
	})

	var out Session
	err = jar.Get(req, &out)
	if !errors.Is(err, pasetojar.ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken, got %v", err)
	}
}

func TestGet_TamperedToken(t *testing.T) {
	key := paseto.NewV4SymmetricKey()
	jar, err := pasetojar.New("session", key, defaultParams())
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	// Create a valid cookie
	w := httptest.NewRecorder()
	in := Session{UID: 42, Role: "admin", Name: "Bob"}
	if err := jar.Set(w, in); err != nil {
		t.Fatalf("Set error: %v", err)
	}
	c, ok := cookieFromRecorder(w, "session")
	if !ok {
		t.Fatal("cookie not set")
	}

	// Tamper with the token
	c.Value = c.Value[:len(c.Value)-5] + "XXXXX"

	var out Session
	err = jar.Get(reqWithCookie(c), &out)
	if !errors.Is(err, pasetojar.ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken for tampered token, got %v", err)
	}
}

func TestGet_WrongKey(t *testing.T) {
	jar1, err := pasetojar.New("session", paseto.NewV4SymmetricKey(), defaultParams())
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	jar2, err := pasetojar.New("session", paseto.NewV4SymmetricKey(), defaultParams())
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	// Create a cookie with jar1
	w := httptest.NewRecorder()
	in := Session{UID: 42, Role: "admin", Name: "Bob"}
	if err := jar1.Set(w, in); err != nil {
		t.Fatalf("Set error: %v", err)
	}
	c, ok := cookieFromRecorder(w, "session")
	if !ok {
		t.Fatal("cookie not set")
	}

	// Try to read with jar2 (different key)
	var out Session
	err = jar2.Get(reqWithCookie(c), &out)
	if !errors.Is(err, pasetojar.ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken for wrong key, got %v", err)
	}
}

func TestGet_ExpiredToken(t *testing.T) {
	key := paseto.NewV4SymmetricKey()
	params := defaultParams()
	params.MaxAge = 1 * time.Millisecond // Very short expiration
	jar, err := pasetojar.New("session", key, params)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	// Create a cookie
	w := httptest.NewRecorder()
	in := Session{UID: 42, Role: "admin", Name: "Bob"}
	if err := jar.Set(w, in); err != nil {
		t.Fatalf("Set error: %v", err)
	}
	c, ok := cookieFromRecorder(w, "session")
	if !ok {
		t.Fatal("cookie not set")
	}

	// Wait for token to expire
	time.Sleep(10 * time.Millisecond)

	var out Session
	err = jar.Get(reqWithCookie(c), &out)
	if !errors.Is(err, pasetojar.ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken for expired token, got %v", err)
	}
}

func TestClear(t *testing.T) {
	jar, err := pasetojar.New("session", paseto.NewV4SymmetricKey(), defaultParams())
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	w := httptest.NewRecorder()

	jar.Clear(w)

	c, ok := cookieFromRecorder(w, "session")
	if !ok {
		t.Fatal("cookie not set")
	}
	if c.MaxAge != -1 {
		t.Errorf("expected MaxAge=-1, got %d", c.MaxAge)
	}
	if c.Value != "" {
		t.Errorf("expected empty value, got %q", c.Value)
	}
	if !c.Expires.Before(time.Now()) {
		t.Errorf("expected Expires to be in the past, got %v", c.Expires)
	}
}

func TestSet_PersistentCookie(t *testing.T) {
	key := paseto.NewV4SymmetricKey()
	params := defaultParams()
	params.MaxAge = 24 * time.Hour
	jar, err := pasetojar.New("session", key, params)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	w := httptest.NewRecorder()
	in := Session{UID: 42, Role: "admin", Name: "Bob"}
	if err := jar.Set(w, in); err != nil {
		t.Fatalf("Set error: %v", err)
	}

	c, ok := cookieFromRecorder(w, "session")
	if !ok {
		t.Fatal("cookie not set")
	}

	// Persistent cookie should have MaxAge and Expires set
	expectedMaxAge := int(24 * time.Hour / time.Second)
	if c.MaxAge != expectedMaxAge {
		t.Errorf("expected MaxAge=%d, got %d", expectedMaxAge, c.MaxAge)
	}
	if c.Expires.IsZero() {
		t.Error("expected non-zero Expires for persistent cookie")
	}

	// Check that Expires is approximately 24 hours from now
	expectedExpires := time.Now().Add(24 * time.Hour)
	if c.Expires.Before(expectedExpires.Add(-1*time.Minute)) || c.Expires.After(expectedExpires.Add(1*time.Minute)) {
		t.Errorf("Expires is not approximately 24 hours from now: got %v", c.Expires)
	}
}

func TestSet_CookieAttributes(t *testing.T) {
	key := paseto.NewV4SymmetricKey()
	params := pasetojar.CookieParams{
		Path:     "/api",
		Domain:   "example.com",
		MaxAge:   1 * time.Hour,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	jar, err := pasetojar.New("session", key, params)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	w := httptest.NewRecorder()
	in := Session{UID: 42, Role: "admin", Name: "Bob"}
	if err := jar.Set(w, in); err != nil {
		t.Fatalf("Set error: %v", err)
	}

	c, ok := cookieFromRecorder(w, "session")
	if !ok {
		t.Fatal("cookie not set")
	}

	if c.Path != "/api" {
		t.Errorf("expected Path=/api, got %s", c.Path)
	}
	if c.Domain != "example.com" {
		t.Errorf("expected Domain=example.com, got %s", c.Domain)
	}
	if !c.Secure {
		t.Error("expected Secure=true")
	}
	if !c.HttpOnly {
		t.Error("expected HttpOnly=true")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Errorf("expected SameSite=Strict, got %v", c.SameSite)
	}
}

func TestGetters(t *testing.T) {
	key := paseto.NewV4SymmetricKey()
	params := defaultParams()
	jar, err := pasetojar.New("test-session", key, params)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	if jar.Name() != "test-session" {
		t.Errorf("expected Name()=test-session, got %s", jar.Name())
	}

	if jar.Key() != key {
		t.Error("Key() returned different key")
	}

	returnedParams := jar.Params()
	if returnedParams.Path != params.Path {
		t.Errorf("expected Path=%s, got %s", params.Path, returnedParams.Path)
	}
	if returnedParams.MaxAge != params.MaxAge {
		t.Errorf("expected MaxAge=%v, got %v", params.MaxAge, returnedParams.MaxAge)
	}
	if returnedParams.Secure != params.Secure {
		t.Errorf("expected Secure=%v, got %v", params.Secure, returnedParams.Secure)
	}
}

func TestNew_InvalidMaxAge(t *testing.T) {
	key := paseto.NewV4SymmetricKey()

	// Test MaxAge = 0
	params := defaultParams()
	params.MaxAge = 0
	_, err := pasetojar.New("session", key, params)
	if !errors.Is(err, pasetojar.ErrInvalidMaxAge) {
		t.Errorf("expected ErrInvalidMaxAge for MaxAge=0, got %v", err)
	}

	// Test MaxAge < 0
	params.MaxAge = -1 * time.Hour
	_, err = pasetojar.New("session", key, params)
	if !errors.Is(err, pasetojar.ErrInvalidMaxAge) {
		t.Errorf("expected ErrInvalidMaxAge for MaxAge<0, got %v", err)
	}
}

