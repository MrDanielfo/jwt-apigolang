package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"./driver"
	"./models"
	"./utils"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/subosito/gotenv"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

func init() {
	gotenv.Load()
}

func main() {
	db = driver.ConnectDB()

	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/signup", signUp).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/protected", tokenVerifyMiddleware(protectedEndpoint)).Methods("GET")

	log.Println("Listen on port 8000...")
	server := http.ListenAndServe(":8000", router)
	log.Fatal(server)
}

func signUp(w http.ResponseWriter, r *http.Request) {

	var user models.User
	var error models.Error
	json.NewDecoder(r.Body).Decode(&user)

	if user.Email == "" || user.Password == "" {
		error.Message = "Fields are required"
		// status bad request
		utils.RespondWithError(w, http.StatusBadRequest, error)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)

	if err != nil {
		log.Fatal(err)
	}
	// Se tiene que convertir a string porque nuestra bd espera el campo como de tipo string
	user.Password = string(hash)

	// Se crea la consulta SQL
	stmt := "INSERT INTO users (email, pass) VALUES($1, $2) RETURNING id"
	err = db.QueryRow(stmt, user.Email, user.Password).Scan(&user.ID)

	if err != nil {
		error.Message = "Server error"
		utils.RespondWithError(w, http.StatusInternalServerError, error)
	}

	user.Password = ""
	w.Header().Set("Content-Type", "application/json")
	utils.ResponseJSON(w, user)

}

func generateToken(user models.User) (string, error) {
	var err error
	secret := os.Getenv("SECRET")
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"iss":   "course",
	})

	tokenString, err := token.SignedString([]byte(secret))

	if err != nil {
		log.Fatal(err)
	}

	return tokenString, nil

}

func login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var user models.User
	var jwt models.JWT
	var error models.Error

	json.NewDecoder(r.Body).Decode(&user)

	if user.Email == "" || user.Password == "" {
		error.Message = "Fields are required"
		// status bad request
		utils.RespondWithError(w, http.StatusBadRequest, error)
		return
	}
	/* Este password tiene que ir aquí para que tome el valor que se le envía por JSON */
	password := user.Password
	/* Revisar si el usuario está en la base de datos */
	row := db.QueryRow("SELECT * FROM users WHERE email = $1", user.Email)
	err := row.Scan(&user.ID, &user.Email, &user.Password)

	if err != nil {
		if err == sql.ErrNoRows {
			error.Message = "The user does not exist"
			utils.RespondWithError(w, http.StatusBadRequest, error)
			return
		} else {
			log.Fatal(err)
		}
	}

	// Comparar passwords
	hashedPassword := user.Password

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))

	if err != nil {
		error.Message = "Invalid credentials"
		utils.RespondWithError(w, http.StatusUnauthorized, error)
		return
	}

	token, err := generateToken(user)

	if err != nil {
		log.Fatal(err)
	}

	w.WriteHeader(http.StatusOK)
	jwt.Token = token

	utils.ResponseJSON(w, jwt)
	// spew.Dump(user)

}

func protectedEndpoint(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Println("Hallo! Wie alt bist du?")
}

func tokenVerifyMiddleware(next http.HandlerFunc) http.HandlerFunc {
	// fmt.Println("token verify invoked")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var errorObject models.Error
		authHeader := r.Header.Get("Authorization")
		bearerToken := strings.Split(authHeader, " ")
		// fmt.Println(bearerToken)
		if len(bearerToken) == 2 {
			authToken := bearerToken[1]
			// verificar si el token es válido
			token, error := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("There was an error")
				}
				return []byte(os.Getenv("SECRET")), nil
			})

			if error != nil {
				errorObject.Message = error.Error()
				utils.RespondWithError(w, http.StatusUnauthorized, errorObject)
				return
			}

			if token.Valid {
				next.ServeHTTP(w, r)
			} else {
				errorObject.Message = error.Error()
				utils.RespondWithError(w, http.StatusUnauthorized, errorObject)
				return
			}

		} else {
			errorObject.Message = "Invalid token"
			utils.RespondWithError(w, http.StatusUnauthorized, errorObject)
			return
		}
		// fmt.Println(bearerToken)
	})

}
