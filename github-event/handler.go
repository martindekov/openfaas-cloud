package function

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/alexellis/hmac"
	"github.com/openfaas/openfaas-cloud/sdk"
)

// Source name for this function when auditing
const Source = "github-event"

// Handle a serverless request
func Handle(req []byte) string {
	eventHeader := os.Getenv("Http_X_Github_Event")
	xHubSignature := os.Getenv("Http_X_Hub_Signature")

	if eventHeader != "push" &&
		eventHeader != "installation_repositories" &&
		eventHeader != "integration_installation" &&
		eventHeader != "installation" {

		auditEvent := sdk.AuditEvent{
			Message: "bad event: " + eventHeader,
			Source:  Source,
		}

		sdk.PostAudit(auditEvent)

		return fmt.Sprintf("%s cannot handle event: %s", Source, eventHeader)
	}

	if eventHeader == "push" {
		headers := map[string]string{
			"X-Hub-Signature": xHubSignature,
			"X-GitHub-Event":  eventHeader,
			"Content-Type":    "application/json",
		}

		body, statusCode, err := forward(req, "github-push", headers)

		if statusCode == http.StatusOK {
			return fmt.Sprintf("Forwarded to function: %d, %s", statusCode, body)
		}

		if err != nil {
			return err.Error()
		}

		return body
	}

	if eventHeader == "installation" ||
		eventHeader == "installation_repositories" ||
		eventHeader == "integration_installation" {

		shouldValidate := os.Getenv("validate_hmac")
		if len(shouldValidate) > 0 && (shouldValidate == "1" || shouldValidate == "true") {
			webhookSecretKey, secretErr := sdk.ReadSecret("github-webhook-secret")
			if secretErr != nil {
				return secretErr.Error()
			}

			validateErr := hmac.Validate(req, xHubSignature, webhookSecretKey)
			if validateErr != nil {
				log.Fatal(validateErr)
			}
		}

		event := InstallationRepositoriesEvent{}
		err := json.Unmarshal(req, &event)
		if err != nil {
			return err.Error()
		}

		fmt.Printf("event.Action: %s\n", event.Action)

		switch event.Action {
		case "created", "added":

			addedVal := ""
			if event.RepositoriesAdded != nil {
				for _, added := range event.RepositoriesAdded {
					addedVal += added.FullName + ", "
				}
			}
			if event.Repositories != nil {
				for _, added := range event.Repositories {
					addedVal += added.FullName + ", "
				}
			}

			auditEvent := sdk.AuditEvent{
				Message: event.Installation.Account.Login + " added repositories: " + addedVal,
				Source:  Source,
			}

			sdk.PostAudit(auditEvent)

		case "removed":
			garbageRequests := []GarbageRequest{}
			for _, repo := range event.RepositoriesRemoved {
				fmt.Printf("Need to remove: %s.\n", repo.FullName)

				garbageRequests = append(garbageRequests,
					GarbageRequest{
						Owner:     event.Installation.Account.Login,
						Repo:      repo.Name,
						Functions: []string{},
					},
				)
			}
			garbageCollect(garbageRequests)
			break
		case "deleted":
			garbageRequests := []GarbageRequest{}
			owner := event.Installation.Account.Login
			fmt.Printf("Need to remove all repos for owner: %s.\n", owner)

			garbageRequests = append(garbageRequests,
				GarbageRequest{
					Owner:     owner,
					Repo:      "*",
					Functions: []string{},
				},
			)

			garbageCollect(garbageRequests)

			break
		}

	}

	return fmt.Sprintf("Message received with event: %s", eventHeader)
}

func garbageCollect(garbageRequests []GarbageRequest) error {
	client := http.Client{}

	suffix := os.Getenv("dns_suffix")
	gatewayURL := os.Getenv("gateway_url")

	gatewayURL = sdk.CreateServiceURL(gatewayURL, suffix)

	payloadSecret, err := sdk.ReadSecret("payload-secret")
	if err != nil {
		return err
	}

	for _, garbageRequest := range garbageRequests {

		body, _ := json.Marshal(garbageRequest)
		bodyReader := bytes.NewReader(body)
		req, _ := http.NewRequest(http.MethodPost, gatewayURL+"function/garbage-collect", bodyReader)

		digest := hmac.Sign(body, []byte(payloadSecret))
		req.Header.Add(sdk.CloudSignatureHeader, "sha1="+hex.EncodeToString(digest))

		res, err := client.Do(req)
		if err != nil {
			return err
		}
		if res.Body != nil {
			defer res.Body.Close()
		}
		if res.StatusCode != http.StatusOK {
			resBody, _ := ioutil.ReadAll(res.Body)
			fmt.Printf("Error in garbageCollect: %s\n", resBody)
		}
	}
	return nil
}

type GarbageRequest struct {
	Functions []string `json:"functions"`
	Repo      string   `json:"repo"`
	Owner     string   `json:"owner"`
}

type InstallationRepositoriesEvent struct {
	Action       string `json:"action"`
	Installation struct {
		Account struct {
			Login string
		}
	} `json:"installation"`
	RepositoriesRemoved []Installation `json:"repositories_removed"`
	RepositoriesAdded   []Installation `json:"repositories_added"`
	Repositories        []Installation `json:"repositories"`
}

type Installation struct {
	Name     string `json:"name"`
	FullName string `json:"full_name"`
}

func forward(req []byte, function string, headers map[string]string) (string, int, error) {
	payloadSecret, err := sdk.ReadSecret("payload-secret")
	if err != nil {
		return "", http.StatusInternalServerError, err
	}

	c := http.Client{}

	suffix := os.Getenv("dns_suffix")
	gatewayURL := os.Getenv("gateway_url")

	gatewayURL = sdk.CreateServiceURL(gatewayURL, suffix)

	bodyReader := bytes.NewBuffer(req)
	pushReq, _ := http.NewRequest(http.MethodPost, gatewayURL+"function/"+function, bodyReader)
	digest := hmac.Sign(req, []byte(payloadSecret))
	pushReq.Header.Add(sdk.CloudSignatureHeader, "sha1="+hex.EncodeToString(digest))

	for k, v := range headers {
		pushReq.Header.Add(k, v)
	}

	res, err := c.Do(pushReq)
	if err != nil {
		msg := "cannot post to " + function + ": " + err.Error()
		auditEvent := sdk.AuditEvent{
			Message: msg,
			Source:  Source,
		}
		sdk.PostAudit(auditEvent)
		return "", http.StatusInternalServerError, fmt.Errorf(msg)
	}

	if res.Body != nil {
		defer res.Body.Close()
	}
	body, _ := ioutil.ReadAll(res.Body)

	if res.StatusCode != http.StatusOK {
		err = fmt.Errorf(string(body))
	}

	return string(body), res.StatusCode, err
}
