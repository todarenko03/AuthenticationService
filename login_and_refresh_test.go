package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
)

func TestLoginAndRefreshHandler(t *testing.T) {
	// Тест работает при запуске сервера на 8080 порту
	guid := "test"
	resp, err := http.Get("http://127.0.0.1:8080" + "/login?guid=" + guid)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, but got %d", http.StatusOK, resp.StatusCode)
	}

	var responseBody2 struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	err = json.NewDecoder(resp.Body).Decode(&responseBody2)
	if err != nil {
		t.Fatal(err)
	}

	refreshToken := responseBody2.RefreshToken
	if err != nil {
		t.Fatal(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	values := url.Values{}
	values.Set("authorization", refreshToken)
	values.Set("user_id", guid)
	resp, err = http.PostForm("http://127.0.0.1:8080"+"/refresh", values)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, but got %d", http.StatusOK, resp.StatusCode)
	}
}
