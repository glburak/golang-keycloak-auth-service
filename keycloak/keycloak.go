package keycloak

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/Nerzal/gocloak"
)

type UserCreate struct {
	Username  string `json:"username"`
	FirstName string `json:"firstname"`
	LastName  string `json:"lastname"`
	Email     string `json:"email"`
	Password  string `json:"password"`
}
type Message struct {
	Text  string       `json:"msg"`
	Token *gocloak.JWT `json:"token"`
}
type AccessToken struct {
	Atoken string `json:"access_token"`
}

func KeycloakConnection() (*gocloak.JWT, context.Context, *gocloak.GoCloak) {

	client := gocloak.NewClient(os.Getenv("KEYCLOAK_URL"))
	restyClient := client.RestyClient()
	restyClient.SetDebug(true)
	restyClient.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	ctx := context.Background()
	token, err := client.LoginAdmin(ctx, os.Getenv("KEYCLOAK_USER"), os.Getenv("KEYCLOAK_PASSWORD"), os.Getenv("KEYCLOAK_REALM"))
	if err != nil {

		log.Println("Hata oluştu:", err)

	} else {
		log.Printf(token.AccessToken)
	}
	return token, ctx, client
}

func CreateUser(w http.ResponseWriter, r *http.Request) {

	accessToken, ctx, client := KeycloakConnection()

	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// JSON veriyi User yapısına decode etme
	var user UserCreate
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid JSON data", http.StatusBadRequest)
		return
	}

	userKeycloak := gocloak.User{
		FirstName: &user.FirstName,
		LastName:  &user.LastName,
		Email:     &user.Email,
		Enabled:   gocloak.BoolP(true),
		Username:  &user.Username,
	}

	_, err = client.CreateUser(ctx, accessToken.AccessToken, os.Getenv("KEYCLOAK_REALM"), userKeycloak)

	if err != nil {

		message := Message{
			Text: err.Error(),
		}
		json.NewEncoder(w).Encode(message)
		//w.Write()
		w.WriteHeader(http.StatusConflict)
		w.Header().Set("Content-Type", "application/json")

	} else {
		message := Message{
			Text: "user created successfully",
		}
		w.WriteHeader(http.StatusOK)

		json.NewEncoder(w).Encode(message)
		w.Header().Set("Content-Type", "application/json")

	}

}
func UserLogin(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	var user UserCreate
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid JSON data", http.StatusBadRequest)
		return
	}
	username := user.Username
	password := user.Password
	client := gocloak.NewClient(os.Getenv("KEYCLOAK_URL"))
	ctx := context.Background()

	token, err2 := client.Login(ctx, os.Getenv("KEYCLOAK_CLIENT_ID"), os.Getenv("KEYCLOAK_CLIENT_SECRET"), os.Getenv("KEYCLOAK_REALM"), username, password)

	if err2 != nil {

		message := Message{
			Text: "Login Error",
		}
		w.WriteHeader(http.StatusUnauthorized)

		json.NewEncoder(w).Encode(message)
		w.Header().Set("Content-Type", "application/json")

	} else {

		w.WriteHeader(http.StatusOK)

		json.NewEncoder(w).Encode(token)

		w.Header().Set("Content-Type", "application/json")

	}

}

func IsLogin(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	client := gocloak.NewClient(os.Getenv("KEYCLOAK_URL"))
	ctx := context.Background()
	var atoken AccessToken
	tokenErr := json.NewDecoder(r.Body).Decode(&atoken)
	if tokenErr != nil {
		http.Error(w, "Invalid JSON data", http.StatusBadRequest)
		return
	}
	fmt.Println(atoken.Atoken)
	rptResult, err := client.RetrospectToken(ctx, atoken.Atoken, os.Getenv("KEYCLOAK_CLIENT_ID"), os.Getenv("KEYCLOAK_CLIENT_SECRET"), os.Getenv("KEYCLOAK_REALM"))

	if !*rptResult.Active {
		message := Message{
			Text: "Login Error",
		}
		w.WriteHeader(http.StatusUnauthorized)

		json.NewEncoder(w).Encode(message)
		fmt.Println("Token is not active")

	} else {

		message := Message{
			Text: "Login is Success",
		}
		w.WriteHeader(http.StatusOK)

		json.NewEncoder(w).Encode(message)
		fmt.Println("Token is active")
	}

	if err != nil {
		fmt.Println("Inspection failed:" + err.Error())
	}

}
