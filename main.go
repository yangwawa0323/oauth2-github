package main

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v3"

	"github.com/gin-gonic/gin"
)

var red = color.New(color.FgHiRed).SprintfFunc()
var yellow = color.New(color.FgHiYellow).SprintfFunc()
var state, _ = randToken(12)

const authorize_url = "https://github.com/login/oauth/authorize"
const token_url = "https://github.com/login/oauth/access_token"
const user_url = "https://api.github.com/user"

// const repo_url_pattern = "https://api.github.com/users/%s/repos"
const user_repos_url = "https://api.github.com/user/repos"

// https://api.github.com/users/yangwawa0323/repos
//
//go:embed templates/*
var server embed.FS

type GitUser struct {
	Login   string `json:"login"`
	ID      int    `json:"id"`
	Avatar  string `json:"avatar_url"`
	RepoURL string `json:"repos_url"`
}
type Repo struct {
	ID      int     `json:"id"`
	Name    string  `json:"name"`
	HtmlURL string  `json:"html_url"`
	Owner   GitUser `json:"owner"`
}

func debug(message string) {
	fmt.Printf("%s %s\n\n", yellow("[DEBUG] : "), red(message))
}

func abort(ctx *gin.Context, err error) {
	if err != nil {
		ctx.AbortWithStatus(http.StatusBadRequest)
	}
}

func main() {

	router := gin.Default()

	templ := template.Must(template.New("").ParseFS(server, "templates/*.tmpl"))
	router.SetHTMLTemplate(templ)
	// router.Use(static.Serve("/", EmbedFolder(server, "templates")))

	// https://github.com/login/oauth/authorize?access_type=offline&client_id=2b0fd37061dc061aaf4b&response_type=code&scope=user+repo&state=state
	// https://github.com/login/oauth/authorize?client_id=&response_type=code&scope=user+repo&state=c6792c78adecca9370a7c582
	yamlconfig := setup()
	// debug(fmt.Sprintf("%#v", config))
	config := &oauth2.Config{
		ClientID:     yamlconfig.Github.ClientID,
		ClientSecret: yamlconfig.Github.ClientSecret,
		Scopes:       []string{"user", "public_repo"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  authorize_url,
			TokenURL: token_url,
		},
	}

	router.GET("/", func(ctx *gin.Context) {
		url := config.AuthCodeURL(state)
		ctx.HTML(http.StatusOK, "index.tmpl", gin.H{
			"url": url,
		})
	})

	router.GET("/callback", func(ctx *gin.Context) {
		code := ctx.Query("code")
		rcv_state := ctx.Query("state")
		debug(fmt.Sprintf("code : %s , state: %s \n", code, rcv_state))
		tok, err := config.Exchange(ctx, code)
		if err != nil {
			ctx.AbortWithStatus(http.StatusBadRequest)
			return
		}

		// var err error
		client := config.Client(ctx, tok)
		resp, err := client.Get(user_repos_url)
		abort(ctx, err)
		defer resp.Body.Close()

		var repolist []Repo
		decoder := json.NewDecoder(resp.Body)
		decoder.Decode(&repolist)

		// resp2, err := client.Get(fmt.Sprintf(repo_url_pattern, gituser.Login))
		// abort(ctx, err)
		// defer resp2.Body.Close()
		// decoder := json.NewDecoder(resp.Body)

		ctx.HTML(http.StatusOK, "login.tmpl", gin.H{
			"repolist": repolist,
			"user":     repolist[0].Owner,
		})
	})

	debug("51cloudclass.com oauth2 github repo list example")
	router.Run(":8082")
}

type github struct {
	AppName      string `yaml:"app_name"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
}

type Config struct {
	Github github `yaml:"github"`
}

func setup() *Config {

	config := &Config{}
	ex, err := os.Executable()
	exPath := filepath.Dir(ex)
	confFilepath := fmt.Sprintf("%s/conf/app.yaml", exPath)
	conf, err := os.ReadFile(confFilepath)
	if err != nil {
		debug(confFilepath + " is not exists")
	}
	if err := yaml.Unmarshal(conf, config); err != nil {
		debug("can not unmarshal the " + confFilepath)
		panic(err)
	}
	return config
}

func randToken(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// "{"login":"yangwawa0323","id":6591891,"node_id":"MDQ6VXNlcjY1OTE4OTE=","avatar_url":"https://avatars.githubusercontent.com/u/6591891?v=4","gravatar_id":"","url":"https://api.github.com/users/yangwawa0323","html_url":"https://github.com/yangwawa0323","followers_url":"https://api.github.com/users/yangwawa0323/followers","following_url":"https://api.github.com/users/yangwawa0323/following{/other_user}","gists_url":"https://api.github.com/users/yangwawa0323/gists{/gist_id}","starred_url":"https://api.github.com/users/yangwawa0323/starred{/owner}{/repo}","subscriptions_url":"https://api.github.com/users/yangwawa0323/subscriptions","organizations_url":"https://api.github.com/users/yangwawa0323/orgs","repos_url":"https://api.github.com/users/yangwawa0323/repos","events_url":"https://api.github.com/users/yangwawa0323/events{/privacy}","received_events_url":"https://api.github.com/users/yangwawa0323/received_events","type":"User","site_admin":false,"name":null,"company":"Cloudclass","blog":"","location":"HuNan ChangSha","email":null,"hireable":null,"bio":null,"twitter_username":null,"public_repos":160,"public_gists":3,"followers":6,"following":19,"created_at":"2014-02-05T05:23:30Z","updated_at":"2022-12-04T16:21:45Z","private_gists":0,"total_private_repos":11,"owned_private_repos":11,"disk_usage":517904,"collaborators":0,"two_factor_authentication":false,"plan":{"name":"free","space":976562499,"collaborators":0,"private_repos":10000}}"
