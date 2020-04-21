package userrepository

import (
	"database/sql"
	"log"

	"../../models"
)

type UserRepository struct{}

func logFatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func (u UserRepository) Signup(db *sql.DB, user models.User) models.User {
	// Se crea la consulta SQL
	stmt := "INSERT INTO users (email, pass) VALUES($1, $2) RETURNING id"
	err := db.QueryRow(stmt, user.Email, user.Password).Scan(&user.ID)
	logFatal(err)

	user.Password = ""
	return user
}

func (u UserRepository) Login(db *sql.DB, user models.User) (models.User, error) {
	row := db.QueryRow("SELECT * FROM users WHERE email = $1", user.Email)
	err := row.Scan(&user.ID, &user.Email, &user.Password)
	if err != nil {
		return user, err
	}

	return user, nil
}
