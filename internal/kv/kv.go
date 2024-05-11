package kv

import "sync"

type KeyValueStore struct {
	mu    sync.Mutex
	store map[string]string
}

func NewKeyValueStore() *KeyValueStore {
	return &KeyValueStore{
		store: make(map[string]string),
	}
}

func (k *KeyValueStore) Set(key, value string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.store[key] = value
}

func (k *KeyValueStore) Get(key string) (string, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	value, ok := k.store[key]
	return value, ok
}

func (k *KeyValueStore) Delete(key string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.store, key)
}
