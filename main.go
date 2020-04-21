package main

import (
	"database/sql"
	"log"
	"net/http"

	"./controllers"
	"./driver"
	"github.com/gorilla/mux"
	"github.com/subosito/gotenv"
)

var db *sql.DB

func init() {
	gotenv.Load()
}

func main() {
	db = driver.ConnectDB()
	controller := controllers.Controller{}

	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/signup", controller.Signup(db)).Methods("POST")
	router.HandleFunc("/login", controller.Login(db)).Methods("POST")
	router.HandleFunc("/protected", controller.TokenVerifyMiddleware(controller.ProtectedEndpoint())).Methods("GET")

	log.Println("Listen on port 8000...")
	server := http.ListenAndServe(":8000", router)
	log.Fatal(server)
}
