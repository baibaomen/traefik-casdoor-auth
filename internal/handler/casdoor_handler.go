// Copyright 2021 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package handler

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"traefikcasdoor/internal/config"
	"traefikcasdoor/internal/httpstate"

	"github.com/casdoor/casdoor-go-sdk/auth"
	"github.com/gin-gonic/gin"
)

// 自定义错误类型
var (
	ErrTokenExpired = fmt.Errorf("token has expired")
	ErrInvalidToken = fmt.Errorf("invalid token")
)

type Replacement struct {
	ShouldReplaceBody   bool                `json:"shouldReplaceBody"`
	Body                string              `json:"body"`
	ShouldReplaceHeader bool                `json:"shouldReplaceHeader"`
	Header              map[string][]string `json:"Header"`
}

type TokenInfo struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

func ForwardAuthHandler(c *gin.Context) {
	// 首先尝试获取token
	token, err := c.Cookie("access-token")
	if err == nil {
		// 如果有token，验证token
		if err := verifyToken(token); err == nil {
			ForwardAuthHandlerWithState(c)
			return
		}
		// token无效，尝试刷新
		refreshToken, refreshErr := c.Cookie("refresh-token")
		if refreshErr == nil {
			if newToken, err := refreshAccessToken(refreshToken); err == nil {
				// 存储新token
				storeTokens(c, newToken)
				ForwardAuthHandlerWithState(c)
				return
			}
		}
	}

	// 如果没有token或token无效，检查是否有code和state
	clientcode, err := c.Cookie("client-code")
	if err != nil {
		log.Println("no client code found in cookie")
		ForwardAuthHandlerWithoutState(c)
		return
	}
	clientstate, err := c.Cookie("client-state")
	if err != nil {
		log.Println("no state found in cookie")
		ForwardAuthHandlerWithoutState(c)
		return
	}

	// 获取token并存储
	tokenInfo, err := getAndStoreToken(c, clientcode, clientstate)
	if err != nil {
		log.Printf("invalid code and state: %s\n", err.Error())
		ForwardAuthHandlerWithoutState(c)
		return
	}

	// 存储tokens
	storeTokens(c, tokenInfo)
	ForwardAuthHandlerWithState(c)
}

func ForwardAuthHandlerWithoutState(c *gin.Context) {
	body, _ := ioutil.ReadAll(c.Request.Body)
	state := httpstate.NewState(c.Request.Method, c.Request.Header, body)
	stateNonce, err := stateStorage.SetState(state)
	if err != nil {
		log.Printf("error happened when setting state: %s\n", err.Error())
		c.JSON(http.StatusInternalServerError, err.Error())
		return
	}
	callbackURL := strings.TrimRight(config.CurrentConfig.PluginEndpoint, "/") + "/callback"
	redirectURL := fmt.Sprintf("%s/login/oauth/authorize?client_id=%s&response_type=code&redirect_uri=%s&scope=read&state=%s",
		config.CurrentConfig.CasdoorEndpoint,
		config.CurrentConfig.CasdoorClientId,
		callbackURL,
		strconv.Itoa(stateNonce))

	c.Redirect(307, redirectURL)
}

func ForwardAuthHandlerWithState(c *gin.Context) {
	log.Println("authentication successful")

	var replacement Replacement
	replacement.ShouldReplaceBody = true
	replacement.ShouldReplaceHeader = true

	stateString, _ := c.Cookie("client-state")
	stateNonce, _ := strconv.Atoi(stateString)
	state, err := stateStorage.PopState(stateNonce)
	if err != nil {
		log.Printf("no related state found, state nonce %s\n", stateString)
		replacement.ShouldReplaceBody = false
		replacement.ShouldReplaceHeader = false
		c.JSON(200, replacement)
		return
	}

	replacement.Body = string(state.Body)
	replacement.Header = state.Header
	c.JSON(200, replacement)
}

func CasdoorCallbackHandler(c *gin.Context) {
	stateString := c.Query("state")
	code := c.Query("code")

	var splits = strings.Split(config.CurrentConfig.PluginEndpoint, "://")
	if len(splits) < 2 {
		c.JSON(500, gin.H{
			"error": "invalid webhook address in configuration" + stateString,
		})
		return
	}
	domain := splits[1]
	c.SetCookie("client-code", code, 3600, "/", domain, false, true)
	c.SetCookie("client-state", stateString, 3600, "/", domain, false, true)

	stateNonce, _ := strconv.Atoi(stateString)
	state, err := stateStorage.GetState(stateNonce)
	if err != nil {
		log.Printf("no related state found, state nonce %s\n", stateString)
		c.JSON(500, gin.H{
			"error": "no related state found, state nonce " + stateString,
		})
		return
	}

	scheme := state.Header.Get("X-Forwarded-Proto")
	host := state.Header.Get("X-Forwarded-Host")
	uri := state.Header.Get("X-Forwarded-URI")
	url := fmt.Sprintf("%s://%s%s", scheme, host, uri)
	c.Redirect(307, url)
}

// getAndStoreToken 获取OAuth token
func getAndStoreToken(c *gin.Context, code, state string) (*TokenInfo, error) {
	token, err := auth.GetOAuthToken(code, state)
	if err != nil {
		return nil, fmt.Errorf("failed to get OAuth token: %w", err)
	}

	tokenInfo := &TokenInfo{
		AccessToken:  token.AccessToken,
		TokenType:    token.TokenType,
		ExpiresIn:    token.ExpiresIn,
		RefreshToken: token.RefreshToken,
	}

	return tokenInfo, nil
}

// storeTokens 将tokens存储到cookie中
func storeTokens(c *gin.Context, token *TokenInfo) {
	var splits = strings.Split(config.CurrentConfig.PluginEndpoint, "://")
	if len(splits) < 2 {
		log.Println("invalid webhook address in configuration")
		return
	}
	domain := splits[1]

	// 存储access token
	c.SetCookie("access-token", token.AccessToken, token.ExpiresIn, "/", domain, false, true)

	// 存储refresh token（如果有）
	if token.RefreshToken != "" {
		// refresh token通常有更长的有效期
		c.SetCookie("refresh-token", token.RefreshToken, token.ExpiresIn*2, "/", domain, false, true)
	}
}

// verifyToken 验证JWT token的有效性
func verifyToken(token string) error {
	claims, err := auth.ParseJwtToken(token)
	if err != nil {
		return fmt.Errorf("failed to parse JWT token: %w", err)
	}

	// 验证token是否过期
	if !claims.Valid() {
		return ErrTokenExpired
	}

	// 验证发行者是否正确
	if claims.Issuer != config.CurrentConfig.CasdoorEndpoint {
		return fmt.Errorf("invalid token issuer")
	}

	// 验证客户端ID
	if claims.Audience != config.CurrentConfig.CasdoorClientId {
		return fmt.Errorf("invalid client id in token")
	}

	// 检查token是否即将过期（比如30秒内）
	if time.Until(claims.ExpiresAt.Time) < 30*time.Second {
		return ErrTokenExpired
	}

	return nil
}

// refreshAccessToken 刷新access token
func refreshAccessToken(refreshToken string) (*TokenInfo, error) {
	token, err := auth.RefreshToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	return &TokenInfo{
		AccessToken:  token.AccessToken,
		TokenType:    token.TokenType,
		ExpiresIn:    token.ExpiresIn,
		RefreshToken: token.RefreshToken,
	}, nil
}
