package keymanagerv1

import (
	"bytes"
	"google.golang.org/protobuf/proto"
	"testing"
)

func TestMLDSAOptionsWireRoundTrip(t *testing.T) {
	if KeyType_ML_DSA_65 != 5 || KeyType_RSA_4096 != 4 {
		t.Fatal("key type wire values changed")
	}
	for _, ctx := range [][]byte{nil, []byte("context")} {
		in := &SignDataRequest{KeyId: "pq", Data: []byte("original message"), SignerOpts: &SignDataRequest_MldsaOptions{MldsaOptions: &SignDataRequest_MLDSAOptions{Context: ctx}}}
		encoded, err := proto.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		var out SignDataRequest
		if err := proto.Unmarshal(encoded, &out); err != nil {
			t.Fatal(err)
		}
		if out.GetMldsaOptions() == nil || !bytes.Equal(out.GetMldsaOptions().Context, ctx) || !bytes.Equal(out.Data, in.Data) {
			t.Fatal("explicit pure-message options lost")
		}
		if _, ok := out.SignerOpts.(*SignDataRequest_HashAlgorithm); ok {
			t.Fatal("ML-DSA options confused with unspecified hash")
		}
	}
}
