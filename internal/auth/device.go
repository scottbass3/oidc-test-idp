package auth

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// DeviceRoutes mounts the passwordless device verification UI under /device.
func (h *Handler) DeviceRoutes(r chi.Router) {
	r.Get("/", h.deviceUserCode)
	r.Post("/approve", h.deviceApprove)
}

func (h *Handler) deviceUserCode(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	userCode := r.Form.Get("user_code")
	if userCode == "" {
		h.render.HTML(w, http.StatusOK, "device_usercode", map[string]any{"Title": "Device login"})
		return
	}
	// Validate the user code exists before showing account selection.
	if _, err := h.store.GetDeviceAuthorizationByUserCode(r.Context(), userCode); err != nil {
		h.render.HTML(w, http.StatusOK, "device_usercode", map[string]any{
			"Title": "Device login", "UserCode": userCode, "Error": "Unknown or expired code.",
		})
		return
	}
	users, _ := h.store.DB().ListUsers()
	h.render.HTML(w, http.StatusOK, "device_select", map[string]any{
		"Title": "Approve device", "UserCode": userCode, "Users": users,
	})
}

func (h *Handler) deviceApprove(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	userCode := r.FormValue("user_code")
	switch r.FormValue("action") {
	case "allow":
		// The device token's subject is the user's custom subject (or row id).
		subject := r.FormValue("userID")
		if u, err := h.store.DB().GetUser(subject); err == nil {
			subject = u.SubjectOrID()
		}
		if err := h.store.CompleteDeviceAuthorization(r.Context(), userCode, subject); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		h.render.HTML(w, http.StatusOK, "message", map[string]any{
			"Title": "Approved", "Heading": "Device approved",
			"Body": "You can return to your device.",
		})
	default:
		_ = h.store.DenyDeviceAuthorization(r.Context(), userCode)
		h.render.HTML(w, http.StatusOK, "message", map[string]any{
			"Title": "Denied", "Heading": "Device denied",
			"Body": "The device request was denied.",
		})
	}
}
