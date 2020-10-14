package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"net/http"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"

	"github.com/jinzhu/gorm"

	"github.com/rs/cors"

	_ "github.com/jinzhu/gorm/dialects/postgres"
)

type Contact struct {
	gorm.Model

	Name string

	Number string

	Email string

	About string

	Image string
}

var db *gorm.DB

var err error

func createContact(response http.ResponseWriter, request *http.Request) {
	var contact Contact

	response.Header().Add("content-type", "application/json")

	json.NewDecoder(request.Body).Decode(&contact)

	db.AutoMigrate(&Contact{})

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

	params := mux.Vars(request)

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

	params := mux.Vars(request)

	var contact Contact
	var requestContact Contact

	db.First(&contact, params["id"])

	json.NewDecoder(request.Body).Decode(&requestContact)

	contact.Name = requestContact.Name
	contact.Number = requestContact.Number
	contact.Email = requestContact.Email
	contact.About = requestContact.About
	contact.Image = requestContact.Image

	db.Save(&contact)

	json.NewEncoder(response).Encode(&contact)

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

	router.HandleFunc("/contacts", createContact).Methods("POST")

	router.HandleFunc("/contacts", getContacts).Methods("GET")

	router.HandleFunc("/contacts/{id}", getContact).Methods("GET")

	router.HandleFunc("/contacts/{id}", deleteContact).Methods("DELETE")

	router.HandleFunc("/contacts/{id}", updateContact).Methods("PUT")

	handler := cors.Default().Handler(router)

	log.Fatal(http.ListenAndServe(":"+port, handler))

}
