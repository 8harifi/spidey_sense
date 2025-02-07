package main

import (
	"spidey_sense/proxy"
	"sync"
)

func main() {
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		proxy.StartProxy()
	}()
	wg.Wait()
}
