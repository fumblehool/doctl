package integration

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"os/exec"
	"testing"

	"github.com/sclevine/spec"
	"github.com/stretchr/testify/require"
)

var _ = suite("genai/agent/apikey/delete", func(t *testing.T, when spec.G, it spec.S) {
	var (
		expect *require.Assertions
		cmd    *exec.Cmd
		server *httptest.Server
	)

	it.Before(func() {
		expect = require.New(t)

		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			switch req.URL.Path {
			case "/v2/gen-ai/agents/00000000-0000-4000-8000-000000000000/api_keys/00000000-0000-4000-8000-000000000001":
				auth := req.Header.Get("Authorization")
				if auth != "Bearer some-magic-token" {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}

				if req.Method != http.MethodDelete {
					w.WriteHeader(http.StatusMethodNotAllowed)
					return
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNoContent)
			case "/v2/gen-ai/agents/00000000-0000-4000-8000-000000000005/api_keys/99999999-9999-4999-8999-999999999999":
				auth := req.Header.Get("Authorization")
				if auth != "Bearer some-magic-token" {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}

				if req.Method != http.MethodDelete {
					w.WriteHeader(http.StatusMethodNotAllowed)
					return
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"id":"not_found","message":"The resource you requested could not be found."}`))
			default:
				dump, err := httputil.DumpRequest(req, true)
				if err != nil {
					t.Fatal("failed to dump request")
				}

				t.Fatalf("received unknown request: %s", dump)
			}
		}))
	})

	when("valid apikey ID and agent ID is provided with force flag", func() {
		it("deletes the apikey", func() {
			aliases := []string{"delete", "del", "rm"}

			for _, alias := range aliases {
				cmd = exec.Command(builtBinaryPath,
					"-t", "some-magic-token",
					"-u", server.URL,
					"genai",
					"agent",
					"apikeys",
					alias,
					"00000000-0000-4000-8000-000000000001",
					"--agent-id", "00000000-0000-4000-8000-000000000000",
					"--force",
				)

				output, err := cmd.CombinedOutput()
				expect.NoError(err, fmt.Sprintf("received error output: %s", output))
				expect.Contains(string(output), "API Key deleted successfully")
			}
		})
	})

	when("agent does not exist", func() {
		it("returns a not found error", func() {
			cmd = exec.Command(builtBinaryPath,
				"-t", "some-magic-token",
				"-u", server.URL,
				"genai",
				"agent",
				"apikeys",
				"delete",
				"99999999-9999-4999-8999-999999999999",
				"--agent-id", "00000000-0000-4000-8000-000000000005",
				"--force",
			)

			output, err := cmd.CombinedOutput()
			expect.Error(err)
			expect.Contains(string(output), "404")
		})
	})

	when("force flag is not provided", func() {
		it("prompts for confirmation and aborts", func() {
			cmd = exec.Command(builtBinaryPath,
				"-t", "some-magic-token",
				"-u", server.URL,
				"genai",
				"agent",
				"apikeys",
				"delete",
				"00000000-0000-4000-8000-000000000001",
				"--agent-id", "00000000-0000-4000-8000-000000000000",
			)

			// Since we can't easily provide interactive input, the command should abort
			output, err := cmd.CombinedOutput()
			expect.Error(err)
			expect.Contains(string(output), "operation aborted")
		})
	})

	when("using short flag for force", func() {
		it("deletes the api key with -f flag", func() {
			cmd = exec.Command(builtBinaryPath,
				"-t", "some-magic-token",
				"-u", server.URL,
				"genai",
				"agent",
				"apikeys",
				"delete",
				"00000000-0000-4000-8000-000000000001",
				"--agent-id", "00000000-0000-4000-8000-000000000000",
				"-f",
			)

			output, err := cmd.CombinedOutput()
			expect.NoError(err, fmt.Sprintf("received error output: %s", output))
			expect.Contains(string(output), "API Key deleted successfully")
		})
	})

	when("network connectivity issues", func() {
		it("handles network errors", func() {
			cmd = exec.Command(builtBinaryPath,
				"-t", "some-magic-token",
				"-u", "http://nonexistent-server.example.com",
				"genai",
				"agent",
				"apikeys",
				"delete",
				"00000000-0000-4000-8000-000000000000",
				"--agent-id", "00000000-0000-4000-8000-000000000001",
				"--force",
			)

			output, err := cmd.CombinedOutput()
			expect.Error(err)
			expect.Contains(string(output), "no such host")
		})
	})
})
