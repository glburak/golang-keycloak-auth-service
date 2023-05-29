package main

import (
	"log"
	"net/http"

	keycloak "./keycloak"

)

func main() {

	http.HandleFunc("/user/create", keycloak.CreateUser)
	http.HandleFunc("/user/login", keycloak.UserLogin)
	http.HandleFunc("/user/islogin", keycloak.IsLogin)

	log.Println(http.ListenAndServe(":8081",nil))
}
