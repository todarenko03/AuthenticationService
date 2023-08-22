package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

const (
	refreshTokenTimeLimit = 24 * time.Hour
)

type AccessTokenClaims struct {
	UserID string `json:"user_id"`
	jwt.StandardClaims
}

type RefreshToken struct {
	UserID       string    `bson:"user_id"`
	RefreshToken string    `bson:"refresh_token"`
	ExpiresAt    time.Time `bson:"expires_at"`
}


var (
	session    *mgo.Session
	collection *mgo.Collection
)

func main() {
	session, err := mgo.Dial("mongodb://localhost:27017")
	if err != nil {
		log.Fatal(err)
	}
	err = session.Ping()
	if err != nil {
		log.Fatalf("Failed to connect to the database: %v", err)
	}
	log.Println("Connected to the database")
	defer session.Close()

	collection = session.DB("authentication").C("tokens")

	http.HandleFunc("/login", loginRoute)
	http.HandleFunc("/refresh", refreshRoute)

	log.Fatal(http.ListenAndServe(":8080", nil))
}

func loginRoute(w http.ResponseWriter, r *http.Request) {
	secretKey := os.Getenv("JWT_SECRET_KEY")

	guid := r.URL.Query().Get("guid")

	accessTokenClaims := AccessTokenClaims{
		UserID: guid,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Minute * 20).Unix(),
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, accessTokenClaims)
	accessTokenString, err := accessToken.SignedString([]byte(secretKey))
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	refreshToken := generateRandomToken()
	refreshTokenHash, err := hashToken(refreshToken)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	refreshTokenExp := time.Now().Add(refreshTokenTimeLimit)


	err = collection.Insert(&RefreshToken{
		UserID:       guid,
		RefreshToken: refreshTokenHash,
		ExpiresAt:    refreshTokenExp,
	})
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"access_token": "%s", "refresh_token": "%s"}`, accessTokenString, refreshToken)
}

func refreshRoute(w http.ResponseWriter, r *http.Request) {
	secretKey := os.Getenv("JWT_SECRET_KEY")
	refreshToken := r.PostFormValue("authorization")
	user := r.PostFormValue("user_id")

	var storedRefreshToken RefreshToken
	err := collection.Find(bson.M{"user_id": user}).One(&storedRefreshToken)
	if err != nil {
		log.Println("user: ", user)
		http.Error(w, "Unauthorized2", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(storedRefreshToken.RefreshToken), []byte(refreshToken)); err != nil {
		log.Println("1: ", storedRefreshToken.RefreshToken)
		log.Println("2: ", refreshToken)
		log.Println("3: ", user)
		log.Println(err)
		http.Error(w, "Unauthorized3", http.StatusUnauthorized)
		return
	}

	accessTokenClaims := AccessTokenClaims {
		UserID: storedRefreshToken.UserID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Minute * 20).Unix(),
		},
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, accessTokenClaims)
	accessTokenString, err := accessToken.SignedString([]byte(secretKey))
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"access_token": "%s"`, accessTokenString)
}

func generateRandomToken() string {
	tokenBytes := make([]byte, 32)
	_, err := rand.Read(tokenBytes)
	if err != nil {
		log.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(tokenBytes)
}

func hashToken(token string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}
