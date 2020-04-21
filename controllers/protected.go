package controllers

import (
	"net/http"

	"../utils"
)

type Controller struct{}

func (c Controller) ProtectedEndpoint() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		utils.ResponseJSON(w, "New response")
	}
}
