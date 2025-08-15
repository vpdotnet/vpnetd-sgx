package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type ApiResponse[T any] struct {
	Result string `json:"result"` // "success"
	Data   *T     `json:"data,omitempty"`
	Error  string `json:"error,omitempty"`
}

func PostApi[T any](path string, param any) (*T, error) {
	fullpath := "https://ws.atonline.com/_rest/" + path
	//fullpath := "https://vp.net/_rest/"+path
	buf, err := json.Marshal(param)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(fullpath, "application/json", bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP status %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read API response body: %w", err)
	}

	var res *ApiResponse[T]
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, fmt.Errorf("failed to decode API response: %w", err)
	}

	if res.Result != "success" {
		return nil, fmt.Errorf("API %s: %s", res.Result, res.Error)
	}

	return res.Data, nil
}
