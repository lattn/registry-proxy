package main

import (
	"errors"
	"log/slog"
	"net/http"
	"os"

	echo "github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
)

func main() {
	cfg, err := LoadConfig()
	if err != nil {
		slog.Error("Error loading config:", "error", err)
		os.Exit(1)
	}
	slog.Info("Loaded config:", "config", cfg)

	handler := &handler{cfg: cfg, client: http.DefaultClient}
	app := echo.New()
	app.Use(middleware.RequestLogger())
	app.Use(middleware.Recover())
	defErrHandler := app.HTTPErrorHandler
	app.HTTPErrorHandler = func(c *echo.Context, err error) {
		if r, _ := echo.UnwrapResponse(c.Response()); r != nil && r.Committed {
			return
		}
		if e, ok := errors.AsType[*echo.HTTPError](err); ok {
			_ = c.String(e.Code, e.Message)
			return
		}
		defErrHandler(c, err)
	}

	app.Use(middleware.RequestLogger())
	app.Use(middleware.Recover())

	app.Any("/auth", handler.auth)

	app.Any("/v2", handler.proxyV2)
	app.Any("/v2/*", handler.proxyV2)

	if err := app.Start(cfg.Listen); err != nil {
		slog.Error("Error starting server:", "error", err)
		os.Exit(1)
	}
}
