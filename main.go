package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"

	"github.com/jinzhu/gorm"

	"github.com/rs/cors"

	_ "github.com/jinzhu/gorm/dialects/postgres"
)

type Contact struct {
	gorm.Model

	Name string

	Number string

	Email string `gorm:"primary_key"`

	About string

	Image string
}

type User struct {
	gorm.Model

	Email string `gorm:"primary_key"`

	Password string
}

var db *gorm.DB

var err error

func index(response http.ResponseWriter, request *http.Request) {
	response.WriteHeader(200)
	response.Write([]byte(`Welcome to Phonebook's API`))

}

func createContact(response http.ResponseWriter, request *http.Request) {
	var contact Contact

	response.Header().Add("content-type", "application/json")
    response.Header().Set("Access-Control-Allow-Origin", "*")

	json.NewDecoder(request.Body).Decode(&contact)
	finalResult := make(map[string]interface{})

	db.AutoMigrate(&Contact{})

	message := make(map[string]interface{})

		_, err := validateToken(request)

	if err != nil {
		response.WriteHeader(http.StatusNotFound)
		response.Write([]byte(`{"message": "Pls, provide a valid token"}`))
		return
	}

	if contact.About == "" {
		message["email"] = "Email field is required"

	}
	if contact.Name == "" {
		message["name"] = "Name field is required"

	}
	if contact.Image == "" {
		message["Image"] = "Image field is required"

	}

	if contact.About == ""  || contact.Name == "" || contact.Image == "" {
			finalResult["message"] = message
		finalResult["status"] = 400
		finalResult["success"] = false
		json.NewEncoder(response).Encode(finalResult)
		return
	}


	val := db.Where("email = ?", contact.Email).First(&contact)

	if val.RowsAffected == 1{
		finalResult["message"] = "Email exists already"
		finalResult["status"] = 404
		finalResult["success"] = false
		json.NewEncoder(response).Encode(finalResult)
		return

	}



	db.Create(&contact)

	json.NewEncoder(response).Encode(&contact)

}

func getContacts(response http.ResponseWriter, request *http.Request) {
	response.Header().Add("content-type", "application/json")

	var contacts []Contact
	finalResult := make(map[string]interface{})

	result := db.Find(&contacts)

	if result.Error != nil {
		finalResult["message"] = "Unable to fetch contacts"
		finalResult["status"] = 400
		finalResult["success"] = false
		json.NewEncoder(response).Encode(finalResult)
		return
	}

	if len(contacts) < 1 {
		finalResult["message"] = "No contacts"
		finalResult["status"] = 404
		finalResult["success"] = false
		json.NewEncoder(response).Encode(finalResult)
		return

	}

	finalResult["message"] = "Fetched contacts successfully"
	finalResult["status"] = 200
	finalResult["success"] = true
	finalResult["data"] = contacts
	finalResult["totalContacts"] = len(contacts)

	json.NewEncoder(response).Encode(finalResult)

}

func getContact(response http.ResponseWriter, request *http.Request) {
	response.Header().Add("content-type", "application/json")

	params := mux.Vars(request)
	finalResult := make(map[string]interface{})

	var contact []Contact

	fmt.Print(params["id"])

	result := db.First(&contact, params["id"])

	if result.Error != nil {
		finalResult["message"] = "Unable to fetch contacts"
		finalResult["status"] = 400
		finalResult["success"] = false
		json.NewEncoder(response).Encode(finalResult)
		return
	}

	if len(contact) < 1 {
		finalResult["message"] = "Contact does not exists"
		finalResult["status"] = 404
		finalResult["success"] = false
		json.NewEncoder(response).Encode(finalResult)
		return

	}

	finalResult["message"] = "Fetched contact successfully"
	finalResult["status"] = 200
	finalResult["success"] = true
	finalResult["data"] = contact

	json.NewEncoder(response).Encode(finalResult)

}

func deleteContact(response http.ResponseWriter, request *http.Request) {
	response.Header().Add("content-type", "application/json")
	response.Header().Set("Access-Control-Allow-Origin", "*")
	
	 if (request.Method == "OPTIONS") {
        response.Header().Set("Access-Control-Allow-Headers", "Authorization") // You can add more headers here if needed
    }

	params := mux.Vars(request)


		_, err := validateToken(request)

	if err != nil {
		response.WriteHeader(http.StatusNotFound)
		response.Write([]byte(`{"message": "Pls, provide a valid token"}`))
		return
	}

	var contact []Contact

	db.First(&contact, params["id"])

	finalResult := make(map[string]interface{})

	if &contact == nil {
		finalResult["message"] = "Contact is not available"
		finalResult["status"] = 404
		finalResult["success"] = false
		json.NewEncoder(response).Encode(finalResult)
		return
	}

	db.Delete(&contact, params["id"])
	finalResult["message"] = "Contact deleted successfully"
	finalResult["status"] = 204
	finalResult["success"] = true
	json.NewEncoder(response).Encode(finalResult)
}

func updateContact(response http.ResponseWriter, request *http.Request) {
	response.Header().Add("content-type", "application/json")
    response.Header().Set("Access-Control-Allow-Origin", "*")

	params := mux.Vars(request)

		_, err := validateToken(request)

	if err != nil {
		response.WriteHeader(http.StatusNotFound)
		response.Write([]byte(`{"message": "Pls, provide a valid token"}`))
		return
	}

	var contact Contact

	json.NewDecoder(request.Body).Decode(&contact)
	message := make(map[string]interface{})
	finalResult := make(map[string]interface{})


		if contact.About == "" {
		message["email"] = "Email field is required"

	}
	if contact.Name == "" {
		message["name"] = "Name field is required"

	}
	if contact.Image == "" {
		message["Image"] = "Image field is required"

	}
	if contact.About == ""  || contact.Name == "" || contact.Image == "" {
			finalResult["message"] = message
		finalResult["status"] = 400
		finalResult["success"] = false
		json.NewEncoder(response).Encode(finalResult)
		return
	}


	db.Model(&contact).Where("ID=?", params["id"]).Updates(Contact{Name: contact.Name, Image: contact.Image, About: contact.About, Number: contact.Number, Email: contact.Email})

	json.NewEncoder(response).Encode(&contact)

}

func createUser(response http.ResponseWriter, request *http.Request) {

	response.Header().Add("content-type", "application/json")
	var user User

	db.AutoMigrate(&User{})
	json.NewDecoder(request.Body).Decode(&user)

	message := make(map[string]interface{})
		finalResult := make(map[string]interface{})


	if user.Email == "" {
		message["email"] = "Email field is required"

	}
	if len(user.Password) < 4 {
		message["password"] = "Password length should be greater than 4"

	}
	

	if user.Email == "" || len(user.Password) < 4{
			finalResult["message"] = message
		finalResult["status"] = 400
		finalResult["success"] = false
		json.NewEncoder(response).Encode(finalResult)
		return
	}

		re := regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)

		if !re.MatchString(user.Email) {
			finalResult["message"] = "Pls, enter a valid email"
		finalResult["status"] = 400
		finalResult["success"] = false
		json.NewEncoder(response).Encode(finalResult)
		return
	}


	val := db.Where("email = ?", user.Email).First(&user)

	if val.RowsAffected == 1{
		finalResult["message"] = "Email exists already"
		finalResult["status"] = 404
		finalResult["success"] = false
		json.NewEncoder(response).Encode(finalResult)
		return

	}

	hashedPassword, errPassword := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)

	user.Password = string(hashedPassword)
	if errPassword != nil {
	finalResult["message"] = "Unable to create an account. Try again later"
		finalResult["status"] = 400
		finalResult["success"] = false
		json.NewEncoder(response).Encode(finalResult)
	
		return
	}

	// result, err := collection.InsertOne(ctx, user)
	if err != nil {
		finalResult["message"] = "Unable to create an account. Try again later"
		finalResult["status"] = 400
		finalResult["success"] = false
		json.NewEncoder(response).Encode(finalResult)
	
		return
	}
	db.Create(&user)

	json.NewEncoder(response).Encode(&user)
}

func login(response http.ResponseWriter, request *http.Request){
		response.Header().Add("content-type", "application/json")
	var user User
	var result User

	json.NewDecoder(request.Body).Decode(&user)

	// message := make(map[string]interface{})
		finalResult := make(map[string]interface{})

		val := db.Where("email = ?", user.Email).First(&result)

	if val.RowsAffected == 0{
		finalResult["message"] = "Email or password is incorrect"
		finalResult["status"] = 404
		finalResult["success"] = false
		json.NewEncoder(response).Encode(finalResult)
		return

	}


	err = bcrypt.CompareHashAndPassword([]byte(result.Password), []byte(user.Password))

	if err != nil {
			finalResult["message"] = "Email or password is incorrect"
		finalResult["status"] = 404
		finalResult["success"] = false
		json.NewEncoder(response).Encode(finalResult)
		return
	}

		secret, _ := os.LookupEnv("SECRET")

atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["id"] = result.ID
	atClaims["email"] = result.Email
	// atClaims["exp"] = time.Now().Add(time.Minute * 60).Unix()
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	token, err := at.SignedString([]byte(secret))
	if err != nil {
			finalResult["message"] = "Unable to generate token"
		finalResult["status"] = 404
		finalResult["success"] = false
		json.NewEncoder(response).Encode(finalResult)
		return
	}


	finalResult["message"] = "User logged in successfully"
	finalResult["status"] = 200
	finalResult["success"] = true
	finalResult["token"] = token

	json.NewEncoder(response).Encode(finalResult)

}



func init() {
	// loads values from .env into the system
	if err := godotenv.Load(); err != nil {
		log.Print("No .env file found")
	}
}

func main() {

	port, _ := os.LookupEnv("PORT")
	host, _ := os.LookupEnv("HOST")
	dbPort, _ := os.LookupEnv("DBPORT")
	user, _ := os.LookupEnv("USER")
	dbName, _ := os.LookupEnv("DBNAME")
	password, _ := os.LookupEnv("PASSWORD")

	router := mux.NewRouter()

	psqlInfo := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", host, dbPort, user, password, dbName)

	db, err = gorm.Open("postgres", psqlInfo)

	if err != nil {

		log.Fatal("failed to connect database", err)

	}

	defer db.Close()

	fmt.Println("App has started!!!!")

	router.HandleFunc("/", index).Methods("GET")
	
	router.HandleFunc("/contacts", createContact).Methods("POST")

	router.HandleFunc("/contacts", getContacts).Methods("GET")

	router.HandleFunc("/contacts/{id}", getContact).Methods("GET")

	router.HandleFunc("/contacts/{id}", deleteContact).Methods("DELETE")

	router.HandleFunc("/contacts/{id}", updateContact).Methods("PUT")

	router.HandleFunc("/users", createUser).Methods("POST")

	router.HandleFunc("/login", login).Methods("POST")

	handler := cors.Default().Handler(router)

	log.Fatal(http.ListenAndServe(":"+port, handler))

}


func validateToken(request *http.Request) (string, error) {

	secret, _ := os.LookupEnv("SECRET")

	tokenString := request.Header.Get("Authorization")

	
	if string(tokenString) == "" {
		return "", errors.New("Pls, provide a valid token")
	}
	
	updatedToken := strings.Split(tokenString, " ")[1]
	

	token, _ := jwt.Parse(updatedToken, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return "", errors.New("Pls, provide a valid token")
		}
		return []byte(secret), nil
	})

	var err error

	if token.Valid {
		return "Valid token", err
	}

	return "", errors.New("Pls, provide a valid token")

}