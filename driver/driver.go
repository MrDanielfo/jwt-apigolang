package driver

import (
	"database/sql"
	"log"
	"os"

	"github.com/lib/pq"
)

/*
const (
	host     = "localhost"
	port     = 5432
	user     = "postgres"
	password = "corvettez6"
	dbname   = "golang_mike"
) */

/* 'postgresql://postgres:corvettez6@localhost/golang_mike'
Puede pedir el sslmode=disable
*/

var db *sql.DB

func ConnectDB() *sql.DB {
	pgURL, err := pq.ParseURL(os.Getenv("POSTGRESQL_URL"))

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

	return db
}
