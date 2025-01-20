package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"github.com/rs/cors"
	"golang.org/x/sync/errgroup"
)

type Config struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	AppSecret    string
	DbURL        string
}

type InstagramToken struct {
	AccessToken string `json:"access_token"`
	UserId      int    `json:"user_id"`
	ExpiresIn   int    `json:"expires_in"`
}

type Server struct {
	config Config
	db     *sql.DB
	logger *log.Logger
}

const schema = `
CREATE TABLE IF NOT EXISTS instagram_users (
    id SERIAL PRIMARY KEY,
    instagram_id VARCHAR(255) UNIQUE NOT NULL,
    user_id VARCHAR(255) UNIQUE NOT NULL,
    access_token TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS messages (
    id SERIAL PRIMARY KEY,
    instagram_id VARCHAR(255) NOT NULL,
    message_id VARCHAR(255) UNIQUE NOT NULL,
    message_text TEXT NOT NULL,
    response_text TEXT,
    processed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);`

func NewServer(config Config) (*Server, error) {
	db, err := sql.Open("postgres", config.DbURL)
	if err != nil {
		return nil, fmt.Errorf("error connecting to database: %v", err)
	}

	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("error creating schema: %v", err)
	}

	return &Server{
		config: config,
		db:     db,
		logger: log.New(os.Stdout, "[Server] ", log.LstdFlags),
	}, nil
}

const connectTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>Connect Instagram</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background-color: #f0f2f5;
        }
        .container {
            text-align: center;
            padding: 20px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .connect-button {
            display: inline-block;
            background-color: #0095f6;
            color: white;
            padding: 12px 24px;
            border-radius: 4px;
            text-decoration: none;
            font-weight: bold;
            margin-top: 20px;
        }
        .connect-button:hover {
            background-color: #0081d6;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Connect your Instagram Account</h1>
        <p>Connect your Instagram account to enable AI responses to your DMs</p>
        <a href="{{.AuthURL}}" class="connect-button">Connect Instagram</a>
    </div>
</body>
</html>
`

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	authURL := fmt.Sprintf(
		"https://api.instagram.com/oauth/authorize"+
			"?client_id=%s"+
			"&redirect_uri=%s"+
			"&scope=instagram_business_basic,instagram_business_manage_messages"+
			"&response_type=code",
		s.config.ClientID,
		s.config.RedirectURI,
	)

	tmpl := template.Must(template.New("connect").Parse(connectTemplate))
	tmpl.Execute(w, struct{ AuthURL string }{authURL})
}

func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	token, err := s.exchangeCodeForToken(code)
	if err != nil {
		s.logger.Printf("Error exchanging code for token: %v", err)
		http.Error(w, "Authorization failed", http.StatusInternalServerError)
		return
	}

	upf, err := s.fetchMyUserProfile(token.AccessToken)
	if err != nil {
		http.Error(w, "Authorization failed", http.StatusInternalServerError)
		return
	}
	s.logger.Print(upf)

	expiresAt := time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	if err := s.storeToken(token.UserId, token.AccessToken, expiresAt, upf); err != nil {
		s.logger.Printf("Error storing token: %v", err)
		http.Error(w, "Failed to store authorization", http.StatusInternalServerError)
		return
	}

	w.Write([]byte("Successfully connected your Instagram account! You can close this window."))
}

func (s *Server) exchangeCodeForToken(code string) (*InstagramToken, error) {
	resp, err := http.PostForm(
		"https://api.instagram.com/oauth/access_token",
		url.Values{
			"client_id":     {s.config.ClientID},
			"client_secret": {s.config.ClientSecret},
			"grant_type":    {"authorization_code"},
			"redirect_uri":  {s.config.RedirectURI},
			"code":          {code},
		},
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var token InstagramToken
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, err
	}
	return &token, nil
}

func (s *Server) storeToken(instagramId int, accessToken string, expiresAt time.Time, upf *InstgramUserProfile) error {
	_, err := s.db.Exec(`
        INSERT INTO instagram_users (instagram_id, access_token, expires_at, user_id)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (instagram_id) 
        DO UPDATE SET 
            access_token = EXCLUDED.access_token,
            expires_at = EXCLUDED.expires_at,
            updated_at = CURRENT_TIMESTAMP
    `, instagramId, accessToken, expiresAt, upf.UserId)
	return err
}

func (s *Server) handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		mode := r.URL.Query().Get("hub.mode")
		token := r.URL.Query().Get("hub.verify_token")
		challenge := r.URL.Query().Get("hub.challenge")

		if mode == "subscribe" && token == s.config.AppSecret {
			w.Write([]byte(challenge))
			return
		}
		http.Error(w, "Invalid verification token", http.StatusForbidden)
		return
	}

	event := &InstagramWebhook{}
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		http.Error(w, "Invalid webhook payload", http.StatusBadRequest)
		return
	}

	gr := errgroup.Group{}
	for _, entry := range event.Entry {
		for _, msg := range entry.Messaging {
			gr.Go(func() error {
				return s.handleMessage(msg.Recipient.ID, msg.Sender.ID, msg.Message.Mid, msg.Message.Text)
			})
		}
	}

	if err := gr.Wait(); err != nil {
		s.logger.Printf("%v", err)
	}
	w.WriteHeader(http.StatusOK)
}

type InstagramWebhook struct {
	Object string `json:"object"`
	Entry  []struct {
		ID        string `json:"id"`
		Time      int64  `json:"time"`
		Messaging []struct {
			Sender struct {
				ID string `json:"id"`
			} `json:"sender"`
			Recipient struct {
				ID string `json:"id"`
			} `json:"recipient"`
			Timestamp int64 `json:"timestamp"`
			Message   struct {
				Mid  string `json:"mid"`
				Text string `json:"text"`
			} `json:"message"`
		} `json:"messaging"`
	} `json:"entry"`
}

type InstgramUserProfile struct {
	UserId   string `json:"user_id"`
	Username string `json:"username"`
	Id       string `json:"id"`
}

func (s *Server) fetchMyUserProfile(accessToken string) (*InstgramUserProfile, error) {
	resp, err := http.Get("https://graph.instagram.com/v21.0/me?fields=user_id,username&access_token=" + accessToken)
	if err != nil {
		s.logger.Printf("Error fetching profile: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	var upf *InstgramUserProfile
	if err := json.NewDecoder(resp.Body).Decode(&upf); err != nil {
		s.logger.Printf("Error decoding response: %v", err)
		return nil, err
	}

	return upf, nil
}

func (s *Server) handleMessage(fromID, toID, messageID, text string) error {
	_, err := s.db.Exec(`
        INSERT INTO messages (instagram_id, message_id, message_text)
        VALUES ($1, $2, $3)
    `, fromID, messageID, text)
	if err != nil {
		s.logger.Printf("Error storing message: %v", err)
		return err
	}

	var accessToken string
	err = s.db.QueryRow(`
        SELECT access_token 
        FROM instagram_users 
        WHERE user_id = $1
    `, fromID).Scan(&accessToken)
	if err != nil {
		s.logger.Printf("Error getting access token: %v", err)
		return err
	}

	response := getAIResponse(text)

	if err := s.sendInstagramMessage(toID, response, accessToken); err != nil {
		s.logger.Printf("Error sending reply: %v", err)
		return err
	}

	_, err = s.db.Exec(`
        UPDATE messages 
        SET response_text = $1, processed_at = CURRENT_TIMESTAMP
        WHERE message_id = $2
    `, response, messageID)
	if err != nil {
		s.logger.Printf("Error updating message: %v", err)
		return err
	}
	return nil
}

func getAIResponse(query string) string {
	// Implement the calls to AI chatbot here
	return "Thank you for your message! This is an automated response."
}

func (s *Server) sendInstagramMessage(recieverId, message, accessToken string) error {
	url := "https://graph.instagram.com/v21.0/me/messages"
	payload := map[string]interface{}{
		"recipient": map[string]string{
			"id": recieverId,
		},
		"message": map[string]string{
			"text": message,
		},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to send message: %s", resp.Status)
	}

	return nil
}

func main() {
	config := Config{
		ClientID:     os.Getenv("INSTAGRAM_CLIENT_ID"),
		ClientSecret: os.Getenv("INSTAGRAM_CLIENT_SECRET"),
		RedirectURI:  os.Getenv("REDIRECT_URI"),
		AppSecret:    os.Getenv("APP_SECRET"),
		DbURL:        os.Getenv("DATABASE_URL"),
	}

	server, err := NewServer(config)
	if err != nil {
		log.Fatal(err)
	}

	r := mux.NewRouter()
	handler := cors.Default().Handler(r)
	r.HandleFunc("/connect", server.handleConnect).Methods("GET")
	r.HandleFunc("/oauth/callback", server.handleOAuthCallback).Methods("GET")
	r.HandleFunc("/webhook", server.handleWebhook).Methods("GET", "POST")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, handler))
}
