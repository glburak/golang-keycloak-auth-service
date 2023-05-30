package main

import (
	"log"
	"net/http"

	keycloak "./keycloak"
	"github.com/rs/cors"
)

func main() {

	http.HandleFunc("/user/create", keycloak.CreateUser)
	//http.HandleFunc("/user/login", keycloak.UserLogin)
	http.HandleFunc("/user/islogin", keycloak.IsLogin)
	mux := http.NewServeMux()

	cors := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{
			http.MethodPost,
			http.MethodGet,
		},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: false,
		
	})

	mux.HandleFunc("/user/login", keycloak.UserLogin)

	handler := cors.Handler(mux)
	// cors.Default() setup the middleware with default options being
	// all origins accepted with simple methods (GET, POST). See
	// documentation below for more options.
	log.Println(http.ListenAndServe(":8081", handler))
}
