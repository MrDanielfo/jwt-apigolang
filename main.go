package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

/* 'postgresql://postgres:corvettez6@localhost/golang_mike'
Puede pedir el sslmode=disable
*/

type User struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type JWT struct {
	Token string `json:"token"`
}

type Error struct {
	Message string `json:"message"`
}

var db *sql.DB

/*
const (
	host     = "localhost"
	port     = 5432
	user     = "postgres"
	password = "corvettez6"
	dbname   = "golang_mike"
) */

func main() {
	pgURL, err := pq.ParseURL("postgresql://postgres:corvettez6@localhost/golang_mike?sslmode=disable")

	if err != nil {
		log.Fatal(err)
	}

	db, err = sql.Open("postgres", pgURL)

	if err != nil {
		log.Fatal(err)
	}

	err = db.Ping()

	if err != nil {
		panic(err)
	}

	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/signup", signUp).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/protected", tokenVerifyMiddleware(protectedEndpoint)).Methods("GET")

	log.Println("Listen on port 8000...")
	server := http.ListenAndServe(":8000", router)
	log.Fatal(server)
}

func respondWithError(w http.ResponseWriter, status int, error Error) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(error)
}

func responseJSON(w http.ResponseWriter, data interface{}) {
	json.NewEncoder(w).Encode(data)
}

func signUp(w http.ResponseWriter, r *http.Request) {

	var user User
	var error Error
	json.NewDecoder(r.Body).Decode(&user)

	if user.Email == "" || user.Password == "" {
		error.Message = "Fields are required"
		// status bad request
		respondWithError(w, http.StatusBadRequest, error)
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
		respondWithError(w, http.StatusInternalServerError, error)
	}

	user.Password = ""
	w.Header().Set("Content-Type", "application/json")
	responseJSON(w, user)

}

func generateToken(user User) (string, error) {
	var err error
	secret := "comeonjoinwithmeinthiscourse"
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

	var user User
	var jwt JWT
	var error Error

	json.NewDecoder(r.Body).Decode(&user)

	if user.Email == "" || user.Password == "" {
		error.Message = "Fields are required"
		// status bad request
		respondWithError(w, http.StatusBadRequest, error)
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
			respondWithError(w, http.StatusBadRequest, error)
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
		respondWithError(w, http.StatusUnauthorized, error)
		return
	}

	token, err := generateToken(user)

	if err != nil {
		log.Fatal(err)
	}

	w.WriteHeader(http.StatusOK)
	jwt.Token = token

	responseJSON(w, jwt)
	// spew.Dump(user)

}

func protectedEndpoint(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Println("Hallo! Wie alt bist du?")
}

func tokenVerifyMiddleware(next http.HandlerFunc) http.HandlerFunc {
	// fmt.Println("token verify invoked")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var errorObject Error
		authHeader := r.Header.Get("Authorization")
		bearerToken := strings.Split(authHeader, " ")
		fmt.Println(bearerToken)
		if len(bearerToken) == 2 {
			authToken := bearerToken[1]
			// verificar si el token es válido
			token, error := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("There was an error")
				}
				return []byte("comeonjoinwithmeinthiscourse"), nil
			})

			if error != nil {
				errorObject.Message = error.Error()
				respondWithError(w, http.StatusUnauthorized, errorObject)
				return
			}

			if token.Valid {
				next.ServeHTTP(w, r)
			} else {
				errorObject.Message = error.Error()
				respondWithError(w, http.StatusUnauthorized, errorObject)
				return
			}

		} else {
			errorObject.Message = "Invalid token"
			respondWithError(w, http.StatusUnauthorized, errorObject)
			return
		}
		// fmt.Println(bearerToken)
	})

}
