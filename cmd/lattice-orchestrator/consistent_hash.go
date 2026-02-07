package main

import (
	"fmt"
	"sort"
)

type ringEntry struct {
	hash   uint64
	worker *workerConn
}

type hashRing struct {
	replicas int
	entries  []ringEntry
}

func newHashRing(replicas int) *hashRing {
	if replicas <= 0 {
		replicas = 128
	}
	return &hashRing{replicas: replicas}
}

func (r *hashRing) rebuild(workers []*workerConn) {
	r.entries = r.entries[:0]
	for _, worker := range workers {
		if worker == nil {
			continue
		}
		for i := 0; i < r.replicas; i++ {
			h := hashString(fmt.Sprintf("%s#%d", worker.id, i))
			r.entries = append(r.entries, ringEntry{hash: h, worker: worker})
		}
	}

	sort.Slice(r.entries, func(i, j int) bool {
		return r.entries[i].hash < r.entries[j].hash
	})
}

func (r *hashRing) pick(key string) (*workerConn, bool) {
	return r.pickExcluding(key, nil)
}

func (r *hashRing) pickExcluding(key string, excluded map[string]struct{}) (*workerConn, bool) {
	if len(r.entries) == 0 {
		return nil, false
	}

	h := hashString(key)
	idx := sort.Search(len(r.entries), func(i int) bool {
		return r.entries[i].hash >= h
	})
	if idx == len(r.entries) {
		idx = 0
	}

	for i := 0; i < len(r.entries); i++ {
		entry := r.entries[(idx+i)%len(r.entries)]
		if entry.worker == nil {
			continue
		}
		if excluded != nil {
			if _, skip := excluded[entry.worker.id]; skip {
				continue
			}
		}
		return entry.worker, true
	}

	return nil, false
}

func hashString(s string) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	var h uint64 = offset64
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= prime64
	}
	return h
}
