// Package providing oauth2 authentication
// for go-oneroster-api service
package gorauth

import (
	"database/sql"
	sq "github.com/Masterminds/squirrel"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/go-chi/jwtauth"
	_ "github.com/mattn/go-sqlite3"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	errors "golang.org/x/xerrors"
	"os"
	"time"
)

type conf struct {
	DBDriver string
	DBName   string
	Key      string
	KeyAlg   string
}

var c conf

func init() {
	err := c.envs()
	if err != nil {
		log.Error(err)
	}
}

func Login(u, p string) (string, error) {
	db := c.database()
	defer db.Close()
	err := validateSecret(u, p, db)
	if err != nil {
		log.Infof("Bad login: %v", u)
		log.Error(err)
		//TODO: 401
		return "", err
	}
	t, err := c.createToken(u)
	if err != nil {
		// review
		log.Error(err)
		return "", err
	}
	return t, nil
}

func (c *conf) envs() error {
	var ok bool
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

	c.Key, ok = os.LookupEnv("GOR_AUTH_KEY")
	if !ok {
		return errors.New("No key, set GOR_AUTH_KEY")
	}

	c.KeyAlg, ok = os.LookupEnv("GOR_AUTH_KEYALG")
	if !ok {
		return errors.New("No encrypt algorithm, set GOR_AUTH_KEYALG=HS256")
	}
	return nil
}

func (conf *conf) database() *sql.DB {
	var c *sql.DB
	c, err := sql.Open(conf.DBDriver, conf.DBName)
	if err != nil {
		log.Error(err)
		return c
	}
	return c
}

func getSecret(id string, db *sql.DB) (string, error) {
	var s string
	rows, err := sq.
		Select("client_secret_hash").
		From("creds").
		Where("client_id = ?", id).
		RunWith(db).
		Query()
	if err != nil {
		// todo: placeholder
		return "", err
	}
	for rows.Next() {
		err = rows.Scan(&s)
		if err != nil {
			log.Error(err)
		}
	}
	return s, nil
}

func validateSecret(u, p string, db *sql.DB) error {
	hash, err := getSecret(u, db)
	if err != nil {
		return err
	}
	h := []byte(hash)
	b := []byte(p)
	err = bcrypt.CompareHashAndPassword(h, b)
	if err != nil {
		return err
	}
	return nil
}

func (c *conf) createToken(u string) (string, error) {
	tokenAuth := jwtauth.New(c.KeyAlg, []byte(c.Key), nil)
	_, tokenString, err := tokenAuth.Encode(jwt.MapClaims{
		"aud": u,
		"exp": time.Now(), // implement
	})
	if err != nil {
		return "", err
	}
	return tokenString, nil
}
