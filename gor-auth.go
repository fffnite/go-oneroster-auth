// Package providing oauth2 authentication
// for go-oneroster-api service
package gorauth

import (
	"database/sql"
	sq "github.com/Masterminds/squirrel"
	"github.com/dgrijalva/jwt-go"
	_ "github.com/mattn/go-sqlite3"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	errors "golang.org/x/xerrors"
	"os"
)

type conf struct {
	DBDriver string
	DBName   string
	Key      string
	KeyAlg   string
}

func init() {
	db := database()
	defer db.Close()
	err := verify(u, p, db)
	if err != nil {
		log.Infof("Bad login: %v", u)
		//TODO: 401
	}
	token()
}

func (c *conf) envs() error {
	c.DBDriver, ok = os.LookupEnv("GOR_AUTH_DBDRIVER")
	if c.DBDriver == "" || !ok {
		return errors.New("Unknown Database Driver, set GOR_AUTH_DBDRIVER")
	}
	c.DBName, ok = os.LookupEnv("GOR_AUTH_DBNAME")
	if !ok {
		return errors.New("No Database, set GOR_AUTH_DBNAME")
	}
	if c.DBName == "" {
		c.DBName = ":memory:"
	}
	return nil
}

func database() *sql.DB {
	var c *sql.DB
	dr, db, err := envs()
	if err != nil {
		log.Error(err)
		return c
	}
	c, err := sql.Open(dr, db)
	if err != nil {
		log.Error(err)
		return c
	}
	return c
}

func (db *sql.DB) getSecret(id string) (*sql.Result, error) {
	return sq.
		Select("client_secret_hash").
		From("creds").
		Where("client_id = ?", id).
		RunWith(db).
		Exec()

}

func validateSecret(u, p string, db *sql.DB) error {
	hash, err := db.getSecret(u)
	if err != nil {
		return err
	}
	b := []byte(p)
	err := bcrypt.CompareHashAndPassword(hash, b)
	if err != nil {
		return err
	}
	return
}

func createToken() {
	tokenAuth = jwtauth.New(c.KeyAlg, []byte(c.Key), nil) //nil?
	var1, err, var2 := tokenAuth.Encode(jwt.MapClaims{    // vars?
		"aud": u,
		"exp": time.Now(), // implement
	})
	return to
}
