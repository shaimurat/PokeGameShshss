package main

import (
	"context"
	"encoding/json"
	"go.mongodb.org/mongo-driver/bson"
	"log"
	"net/http"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var collection *mongo.Collection

type User struct {
	ID       primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Email    string             `bson:"email" json:"email"`
	Password string             `bson:"password" json:"password"`
}

func main() {
	// MongoDB connection setup
	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017")
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	// Check the connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}

	// Set collection variable to interact with MongoDB
	collection = client.Database("PokeGame").Collection("users")
	log.Println("Connected to MongoDB!")

	// Routes
	http.Handle("/", http.FileServer(http.Dir("./")))
	http.HandleFunc("/register", registration)

	log.Println("Server running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// Create User
func registration(w http.ResponseWriter, r *http.Request) {
	var user User
	json.NewDecoder(r.Body).Decode(&user)

	result, err := collection.InsertOne(context.TODO(), user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "User created successfully",
		"id":      result.InsertedID,
	})
}
func login(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	objectID, _ := primitive.ObjectIDFromHex(id)

	var user User
	err := collection.FindOne(context.TODO(), bson.M{"_id": objectID}).Decode(&user)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"status": "fail", "message": "User not found"})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"status": "success", "data": user})
}
