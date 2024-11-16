package cache

type Cache[T any] interface {
	Get(key string) (*T, bool)
	Set(key string, msg T, ttl uint32)
	Delete(key string)
	Invalidate()
}
