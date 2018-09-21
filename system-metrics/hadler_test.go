package function

import (
	"encoding/json"
	"testing"

	"github.com/openfaas/faas/gateway/metrics"
)

type FakePrometheusQueryFetcher struct {
}

func (q FakePrometheusQueryFetcher) Fetch(query string) (*metrics.VectorQueryResponse, error) {
	val := []byte(`
{
  "Data": {
    "Result": [
      {
        "Metric": {
          "code": "200",
          "function_name": ""
        },
        "value": [
          1536944521.415,
          "6.0068060449603875"
        ]
      },
      {
        "Metric": {
          "code": "301",
          "function_name": ""
        },
        "value": [
          1536944521.415,
          "2.0068060449603875"
        ]
      },
      {
        "Metric": {
          "code": "500",
          "function_name": ""
        },
        "value": [
          1536944521.415,
          "5.005671704133656"
        ]
      },
      {
        "Metric": {
          "code": "400",
          "function_name": ""
        },
        "value": [
          1536944521.415,
          "1.005671704133656"
        ]
      }
    ]
  }
}
`)
	queryRes := metrics.VectorQueryResponse{}
	err := json.Unmarshal(val, &queryRes)
	return &queryRes, err
}

func makeFakePrometheusQueryFetcher() FakePrometheusQueryFetcher {
	return FakePrometheusQueryFetcher{}
}

func Test_getMetrics(t *testing.T) {
	fakeQuery := makeFakePrometheusQueryFetcher()
	fnName := "testFunc"

	got, _ := getMetrics(fnName, fakeQuery, "60m")

	expected := Metrics{
		Success: 8,
		Failure: 6,
	}

	if expected.Success != got.Success || expected.Failure != got.Failure {
		gotJSON, _ := json.Marshal(got)
		expectedJSON, _ := json.Marshal(expected)

		t.Errorf("Expected %s, but got %v", expectedJSON, gotJSON)
	}
}
