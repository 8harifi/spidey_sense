package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
)

func getRoot(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("got request at /")
	_, err := io.WriteString(w, "Hello World")
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	http.HandleFunc("/", getRoot)

	err := http.ListenAndServe(":8000", nil)
	if err != nil {
		log.Fatal(err)
	}
}
