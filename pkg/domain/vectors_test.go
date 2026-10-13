package domain

import (
	"encoding/json"
	"os"
	"testing"
)

func TestSharedContractVectors(t *testing.T) {
	b, e := os.ReadFile("../../fixtures/domain_vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var vs []struct {
		Input, Value string
		Kind         Kind
		Error        bool
	}
	if e = json.Unmarshal(b, &vs); e != nil {
		t.Fatal(e)
	}
	for _, v := range vs {
		h, e := Normalize(v.Input)
		if v.Error {
			if e == nil {
				t.Fatalf("accepted %q", v.Input)
			}
		} else if e != nil || h.Value != v.Value || h.Kind != v.Kind {
			t.Fatalf("%s => %+v %v", v.Input, h, e)
		}
	}
}
