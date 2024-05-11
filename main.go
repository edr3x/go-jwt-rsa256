package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/edr3x/properjwt/internal/kv"
	"github.com/edr3x/properjwt/internal/tokenize"
)

type Handlers struct {
	store *kv.KeyValueStore
}

func NewHandlers() *Handlers {
	return &Handlers{
		store: kv.NewKeyValueStore(),
	}
}

func main() {
	mux := echo.New()

	h := NewHandlers()

	mux.POST("/login", h.login)
	mux.POST("/register", h.register)

	mux.GET("/user", h.user, echo.WrapMiddleware(IsAutn))

	server := &http.Server{
		Handler: mux,
		Addr:    "0.0.0.0:8080",
	}
	log.Printf("listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

type LoginInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterInput struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func (h *Handlers) register(c echo.Context) error {
	var body RegisterInput
	if err := c.Bind(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}

	_, ok := h.store.Get(body.Email)
	if ok {
		return echo.NewHTTPError(http.StatusBadRequest, "email taken")
	}

	userid := uuid.New()
	h.store.Set(body.Email, userid.String())

	mruser, _ := json.Marshal(body)
	h.store.Set(userid.String(), string(mruser))

	return c.JSON(http.StatusCreated, "created")
}

func (h *Handlers) login(c echo.Context) error {
	var body LoginInput
	if err := c.Bind(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}

	uid, ok := h.store.Get(body.Email)
	if !ok {
		return echo.NewHTTPError(http.StatusNotFound, "Not found")
	}

	data, ok := h.store.Get(uid)
	if !ok {
		return echo.NewHTTPError(http.StatusNotFound, "Not found")
	}

	var structuredData RegisterInput
	if err := json.Unmarshal([]byte(data), &structuredData); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	if structuredData.Password != body.Password {
		return echo.NewHTTPError(http.StatusUnauthorized, "password didn't match")
	}

	token, err := tokenize.Generate(tokenize.Access, uid)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	return c.JSON(http.StatusOK, token)
}

func (h *Handlers) user(c echo.Context) error {
	userId, ok := c.Request().Context().Value("id").(string)
	if !ok {
		userId = ""
	}
	val, ok := h.store.Get(userId)
	if !ok {
		return echo.NewHTTPError(http.StatusNotFound, "Not found")
	}

	var structuredData RegisterInput
	if err := json.Unmarshal([]byte(val), &structuredData); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}
	return c.JSON(http.StatusOK, structuredData)
}

func IsAutn(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		info, err := tokenize.VerifyToken(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		c := context.WithValue(r.Context(), "id", info.Id)
		next.ServeHTTP(w, r.WithContext(c))
	}
	return http.HandlerFunc(fn)
}
