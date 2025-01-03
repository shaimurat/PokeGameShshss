package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"os/signal"
	"time"
)

var (
	collection  *mongo.Collection
	store       *sessions.CookieStore
	rateLimiter = rate.NewLimiter(1, 5)
	logger      = logrus.New()
)

type Pokemon struct {
	ID   primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Name string             `bson:"name" json:"name"`
	Desc string             `bson:"desc" json:"desc"`
	Type string             `bson:"type" json:"type"`
	Path string             `bson:"path" json:"path"`
}

type User struct {
	ID       primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Email    string             `bson:"email" json:"email"`
	Password string             `bson:"password" json:"password"`
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	// Setup logging configuration
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetOutput(os.Stdout)
	logger.SetLevel(logrus.InfoLevel)

	// Graceful shutdown setup
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		<-sigs
		logger.Info("Graceful shutdown initiated")
		cancel()
	}()

	// Load environment variables from .env file
	err = godotenv.Load()
	if err != nil {
		logger.Fatal("Error loading .env file")
	}

	sessionKey := os.Getenv("SESSION_KEY")
	if sessionKey == "" {
		logger.Fatal("SESSION_KEY environment variable is not set")
	}

	store = sessions.NewCookieStore([]byte(sessionKey))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   60 * 60,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
	}

	// MongoDB connection setup
	serverAPI := options.ServerAPI(options.ServerAPIVersion1)
	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017/").SetServerAPIOptions(serverAPI)
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		logger.Fatal(err)
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		logger.Fatal(err)
	}

	collection = client.Database("PokeGame").Collection("users")
	logger.Info("Connected to MongoDB!")

	// Start the HTTP server and handle routes
	http.HandleFunc("/register", rateLimitMiddleware(registration))
	http.HandleFunc("/login", rateLimitMiddleware(login))
	http.HandleFunc("/logout", rateLimitMiddleware(logout))
	http.HandleFunc("/sendEmail", rateLimitMiddleware(sendEmail))
	http.HandleFunc("/checkLoginStatus", rateLimitMiddleware(checkLoginStatus))
	http.HandleFunc("/pokemons", rateLimitMiddleware(getPokemonsHandler))
	http.HandleFunc("/riskyOperation", rateLimitMiddleware(riskyOperationHandler))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loginPage", http.StatusFound)
	})
	http.HandleFunc("/loginPage", rateLimitMiddleware(serveLogin))
	http.HandleFunc("/mainPage", rateLimitMiddleware(serveMain))
	http.HandleFunc("/registerPage", rateLimitMiddleware(serveRegister))
	http.HandleFunc("/pokemonsPage", rateLimitMiddleware(servePokemonsPage))
	http.Handle("/css/", http.StripPrefix("/css/", http.FileServer(http.Dir("./css"))))
	http.Handle("/js/", http.StripPrefix("/js/", http.FileServer(http.Dir("./js"))))
	http.Handle("/pokemons/", http.StripPrefix("/pokemons/", http.FileServer(http.Dir("./pokemons"))))

	// Start the server
	server := &http.Server{
		Addr:    ":8080",
		Handler: http.DefaultServeMux,
	}

	logger.Info("Server running on http://localhost:8080")

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Server failed: %v", err)
		}
	}()

	<-ctx.Done()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Errorf("Error during server shutdown: %v", err)
	}
	logger.Info("Server gracefully stopped")
}

// Handles risky operations that may fail
func riskyOperationHandler(w http.ResponseWriter, r *http.Request) {
	logger.Info("Executing risky operation")

	err := riskyOperation()
	if err != nil {
		logger.WithError(err).Error("Risky operation failed")
		http.Error(w, "Risky operation failed", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Risky operation succeeded"))
}

// Simulates a risky operation with a random failure
func riskyOperation() error {
	if time.Now().Unix()%2 == 0 {
		return fmt.Errorf("simulated error")
	}
	return nil
}

// Middleware to enforce rate limiting
func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !rateLimiter.Allow() {
			logger.Warn("Rate limit exceeded")
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// Handles sending email requests
func sendEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var emailData struct {
		Subject string `json:"subject"`
		Body    string `json:"body"`
	}

	err := json.NewDecoder(r.Body).Decode(&emailData)
	if err != nil {
		http.Error(w, "Invalid data", http.StatusBadRequest)
		return
	}

	// Get user email from session
	session, _ := store.Get(r, "PokeGame")
	userID, ok := session.Values["userID"].(string)
	if !ok {
		http.Error(w, "User not logged in", http.StatusUnauthorized)
		return
	}

	// Retrieve user data from the database
	var user User
	objectID, _ := primitive.ObjectIDFromHex(userID)
	err = collection.FindOne(context.TODO(), bson.M{"_id": objectID}).Decode(&user)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Send email using SMTP
	err = sendEmailUsingSMTP(user.Email, emailData.Subject, emailData.Body)
	if err != nil {
		log.Printf("Error sending email: %v", err)
		http.Error(w, "Failed to send email. Please check server logs.", http.StatusInternalServerError)
		return
	}

	// Respond with success message
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Email sent successfully"})
}

// Sends email using SMTP configuration
func sendEmailUsingSMTP(fromEmail, subject, text string) error {
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"
	username := os.Getenv("SMTP_USER")
	password := os.Getenv("SMTP_PASS")
	toEmail := "hdhdgddh455@gmail.com"
	body := fmt.Sprintf("Subject: %s\n\n%s\n\nFrom: %s", subject, text, fromEmail)

	auth := smtp.PlainAuth("", username, password, smtpHost)

	// Send the email
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, fromEmail, []string{toEmail}, []byte(body))

	return err
}

// Logs out the user by clearing their session
func logout(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "PokeGame")
	session.Values = nil
	session.Options.MaxAge = -1
	session.Save(r, w)

	// Respond with success message
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Logged out"})
}

// Registers a new user by saving their email and password in the database
func registration(w http.ResponseWriter, r *http.Request) {
	var user User
	json.NewDecoder(r.Body).Decode(&user)
	email := user.Email
	password := user.Password
	err := collection.FindOne(context.TODO(), bson.M{"email": email}).Decode(&user)
	if err == nil {
		json.NewEncoder(w).Encode(map[string]string{"status": "fail", "message": "User already exists"})
		http.Error(w, err.Error(), 409)
		return
	}
	if err != mongo.ErrNoDocuments {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	hashedPassword, err := hashPassword(password)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}
	result, err := collection.InsertOne(context.TODO(), bson.M{
		"email":    user.Email,
		"password": hashedPassword,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "User created successfully",
		"id":      result.InsertedID,
	})
}

// Handles user login by validating credentials and saving session data
func login(w http.ResponseWriter, r *http.Request) {
	var reqUser User
	if err := json.NewDecoder(r.Body).Decode(&reqUser); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	var dbUser User
	err := collection.FindOne(context.TODO(), bson.M{"email": reqUser.Email}).Decode(&dbUser)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"status": "fail", "message": "User not found"})
		return
	}

	// Check password
	if !checkPasswordHash(reqUser.Password, dbUser.Password) {
		json.NewEncoder(w).Encode(map[string]string{"status": "fail", "message": "Invalid password"})
		return
	}

	// Store session information
	session, _ := store.Get(r, "PokeGame")
	session.Values["userID"] = dbUser.ID.Hex()
	session.Save(r, w)

	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Login successful"})
}

// Checks the login status by looking for the user session
func checkLoginStatus(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "PokeGame")
	userID, ok := session.Values["userID"].(string)
	if ok && userID != "" {
		json.NewEncoder(w).Encode(map[string]string{"status": "logged_in"})
	} else {
		json.NewEncoder(w).Encode(map[string]string{"status": "not_logged_in"})
	}
}

// Renders login page if user is not logged in
func serveLogin(w http.ResponseWriter, r *http.Request) {
	if checkSession(w, r) {
		http.Redirect(w, r, "/mainPage", http.StatusFound)
		return
	}
	http.ServeFile(w, r, "./login.html")
}

// Renders registration page if user is not logged in
func serveRegister(w http.ResponseWriter, r *http.Request) {
	if checkSession(w, r) {
		http.Redirect(w, r, "/mainPage", http.StatusFound)
		return
	}
	http.ServeFile(w, r, "./register.html")
}

// Renders the main page if the user is logged in
func serveMain(w http.ResponseWriter, r *http.Request) {
	if !checkSession(w, r) {
		http.Redirect(w, r, "/loginPage", http.StatusFound)
		return
	}
	http.ServeFile(w, r, "./main.html")
}

// Hashes the password using bcrypt
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// Compares the plain password with the hashed one
func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// Checks if the user is logged in based on the session
func checkSession(w http.ResponseWriter, r *http.Request) bool {
	session, _ := store.Get(r, "PokeGame")
	userID, ok := session.Values["userID"].(string)
	return ok && userID != ""
}

// Retrieves and returns a list of Pokémon from the database
func getPokemonsHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "PokeGame")
	_, ok := session.Values["userID"]
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var pokemons []Pokemon
	cursor, err := collection.Database().Collection("pokemons").Find(context.TODO(), bson.M{})
	if err != nil {
		http.Error(w, "Failed to fetch pokemons", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.TODO())

	for cursor.Next(context.TODO()) {
		var pokemon Pokemon
		if err := cursor.Decode(&pokemon); err != nil {
			http.Error(w, "Error decoding pokemon data", http.StatusInternalServerError)
			return
		}
		pokemons = append(pokemons, pokemon)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pokemons)
}

// Renders the Pokémon page if the user is logged in
func servePokemonsPage(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "PokeGame")
	_, ok := session.Values["userID"]
	if !ok {
		http.Redirect(w, r, "/loginPage", http.StatusFound)
		return
	}

	http.ServeFile(w, r, "./pokemons.html")
}
