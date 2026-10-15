package validation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// MLClient is a thin HTTP client for the Python inference server. It
// is safe for concurrent use — http.Client internally multiplexes.
type MLClient struct {
	endpoint string
	client   *http.Client
}

// mlRequest is the JSON body posted to /predict.
type mlRequest struct {
	Features []float64 `json:"features"`
}

// MLResponse mirrors the JSON returned by /predict.
type MLResponse struct {
	IsBot      bool    `json:"is_bot"`
	Confidence float64 `json:"confidence"`
	BotProb    float64 `json:"bot_prob"`
}

// NewMLClient builds a client targeting endpoint (e.g.
// "http://127.0.0.1:5001"). The default timeout is 300ms — the
// expectation is that inference is fast; anything slower is treated as
// a service outage and the caller fails closed.
func NewMLClient(endpoint string) *MLClient {
	return &MLClient{
		endpoint: endpoint,
		client: &http.Client{
			Timeout: 300 * time.Millisecond,
		},
	}
}

// Predict sends the feature vector to /predict and returns the
// classification. Any error (network, non-200, decode) is returned
// unchanged so callers can decide whether to fail open or closed.
func (c *MLClient) Predict(ctx context.Context, features []float64) (*MLResponse, error) {
	body, err := json.Marshal(mlRequest{Features: features})
	if err != nil {
		return nil, fmt.Errorf("ml marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost,
		c.endpoint+"/predict",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("ml request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ml do: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Drain body so the connection can be reused.
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("ml status: %d", resp.StatusCode)
	}

	var out MLResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("ml decode: %w", err)
	}
	return &out, nil
}

// Health calls /health — useful at startup to surface obvious
// misconfiguration (wrong URL, ML process not running).
func (c *MLClient) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+"/health", nil)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ml health status: %d", resp.StatusCode)
	}
	return nil
}
