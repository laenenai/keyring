package local

import "testing"

func FuzzOpenRecord(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{WrapFormatVersion})
	f.Add(make([]byte, headerLen))
	f.Add([]byte{0xff, 1, 2, 3})
	f.Fuzz(func(_ *testing.T, record []byte) {
		key := make([]byte, kekMaterialLen)
		_, _ = openRecord(key, record, []byte("aad"))
	})
}
