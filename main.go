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
	rateLimiter = rate.NewLimiter(1, 5) // 1 request per second with a burst of 5
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
	// Setup logging
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

	// Load environment variables
	err := godotenv.Load()
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

	// Start server
	http.HandleFunc("/register", rateLimitMiddleware(registration))
	http.HandleFunc("/login", rateLimitMiddleware(login))
	http.HandleFunc("/logout", rateLimitMiddleware(logout))
	http.HandleFunc("/sendEmail", rateLimitMiddleware(sendEmail))
	http.HandleFunc("/checkLoginStatus", rateLimitMiddleware(checkLoginStatus))
	http.HandleFunc("/pokemons", rateLimitMiddleware(getPokemonsHandler))
	http.HandleFunc("/riskyOperation", rateLimitMiddleware(riskyOperationHandler))
	http.Handle("/", http.FileServer(http.Dir("./")))
	http.HandleFunc("/loginPage", rateLimitMiddleware(serveLogin))
	http.HandleFunc("/mainPage", rateLimitMiddleware(serveMain))
	http.HandleFunc("/registerPage", rateLimitMiddleware(serveIndex))
	http.HandleFunc("/pokemonsPage", rateLimitMiddleware(servePokemonsPage))

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

func riskyOperation() error {
	if time.Now().Unix()%2 == 0 {
		return fmt.Errorf("simulated error")
	}
	return nil
}

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

	// Получаем email пользователя из сессии
	session, _ := store.Get(r, "PokeGame")
	userID, ok := session.Values["userID"].(string)
	if !ok {
		http.Error(w, "User not logged in", http.StatusUnauthorized)
		return
	}

	// Получаем email пользователя из базы данных
	var user User
	objectID, _ := primitive.ObjectIDFromHex(userID)
	err = collection.FindOne(context.TODO(), bson.M{"_id": objectID}).Decode(&user)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Отправка email
	err = sendEmailUsingSMTP(user.Email, emailData.Subject, emailData.Body)
	if err != nil {
		log.Printf("Error sending email: %v", err)
		http.Error(w, "Failed to send email. Please check server logs.", http.StatusInternalServerError)
		return
	}

	// Ответ об успешной отправке
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Email sent successfully"})
}

// Функция для отправки email через SMTP
func sendEmailUsingSMTP(fromEmail, subject, text string) error {

	// SMTP сервер, откуда будет отправляться письмо
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"

	// Логин и пароль для аккаунта отправителя
	username := "isiki.edenovy@gmail.com" // Поменяйте на свою переменную окружения
	password := "lswy dyxe pnjd sjkk"     // Поменяйте на свою переменную окружения

	// Данные письма
	toEmail := "hdhdgddh455@gmail.com"
	body := fmt.Sprintf("Subject: %s\n\n%s\n\nFrom: %s", subject, text, fromEmail)

	// Создаем аутентификацию для отправки письма
	auth := smtp.PlainAuth("", username, password, smtpHost)

	// Отправляем письмо
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, fromEmail, []string{toEmail}, []byte(body))

	return err
}

func logout(w http.ResponseWriter, r *http.Request) {
	// Получаем сессию
	session, _ := store.Get(r, "PokeGame")

	// Удаляем все данные из сессии
	session.Values = nil
	session.Options.MaxAge = -1 // Set session expiry to -1
	session.Save(r, w)          // Save the session

	// Возвращаем ответ о успешном логауте
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Logged out"})
}

// Create User
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
		// Handle any other error (e.g., database connection error)
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

	// Сравниваем пароли
	if !checkPasswordHash(reqUser.Password, dbUser.Password) {
		json.NewEncoder(w).Encode(map[string]string{"status": "fail", "message": "Invalid password"})
		return
	}

	// Если пользователь найден и пароль совпадает, сохраняем сессию
	session, _ := store.Get(r, "PokeGame")
	session.Values["userID"] = dbUser.ID.Hex() // Сохраняем ID пользователя в сессии
	session.Save(r, w)                         // Сохраняем сессию

	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Login successful"})
}
func checkLoginStatus(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "PokeGame")
	userID, ok := session.Values["userID"].(string)
	if ok && userID != "" {
		// Если пользователь залогинен, возвращаем статус logged_in
		json.NewEncoder(w).Encode(map[string]string{"status": "logged_in"})
	} else {
		// Если пользователь не залогинен, возвращаем статус not_logged_in
		json.NewEncoder(w).Encode(map[string]string{"status": "not_logged_in"})
	}
}
func serveLogin(w http.ResponseWriter, r *http.Request) {
	// Если пользователь уже залогинен, перенаправляем на главную страницу
	if checkSession(w, r) {
		http.Redirect(w, r, "/mainPage", http.StatusFound)
		return
	}
	http.ServeFile(w, r, "./login.html")
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	// Если пользователь уже залогинен, перенаправляем на главную страницу
	if checkSession(w, r) {
		http.Redirect(w, r, "/mainPage", http.StatusFound)
		return
	}
	http.ServeFile(w, r, "./index.html")
}

func serveMain(w http.ResponseWriter, r *http.Request) {
	// Если нет активной сессии, редиректим на страницу входа
	if !checkSession(w, r) {
		http.Redirect(w, r, "/loginPage", http.StatusFound)
		return
	}

	// Если сессия существует, показываем main.html
	http.ServeFile(w, r, "./main.html")
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// Compare hashed password with plain text
func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func emailHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "PokeGame")
	userID, ok := session.Values["userID"].(string)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	var user User
	objectID, _ := primitive.ObjectIDFromHex(userID)
	err := collection.FindOne(context.TODO(), bson.M{"_id": objectID}).Decode(&user)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

}
func checkSession(w http.ResponseWriter, r *http.Request) bool {
	// Получаем сессию
	session, _ := store.Get(r, "PokeGame")

	// Проверяем, есть ли в сессии значение userID
	userID, ok := session.Values["userID"].(string)
	if ok && userID != "" {
		return true
	}
	return false
}

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

func servePokemonsPage(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "PokeGame")
	_, ok := session.Values["userID"]
	if !ok {
		http.Redirect(w, r, "/loginPage", http.StatusFound)
		return
	}

	http.ServeFile(w, r, "./pokemons.html")
}
