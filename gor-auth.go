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
)

type conf struct {
	DBDriver string
	DBName   string
	Key      string
	KeyAlg   string
}

func Login(id, secret string) (string, error) {
	var conf *conf
	err := conf.envs()
	if err != nil {
		return "", err
	}
	db := conf.database()
	defer db.Close()
	err := verify(u, p, db)
	if err != nil {
		log.Infof("Bad login: %v", u)
		//TODO: 401
		return "", err
	}
	t := conf.createToken(u)
	return t, nil
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
	if err != nil {
		log.Error(err)
		return c
	}
	c, err := sql.Open(conf.DBDriver, conf.DBName)
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
	return nil
}

func (c *conf) createToken() (string, error) {
	tokenAuth = jwtauth.New(c.KeyAlg, []byte(c.Key), nil)
	_, tokenString, err := tokenAuth.Encode(jwt.MapClaims{
		"aud": u,
		"exp": time.Now(), // implement
	})
	if err != nil {
		return "", err
	}
	return tokenString, nil
}
