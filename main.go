package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/ssocreds"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func main() {
	log.SetFlags(0)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := run(ctx); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return err
	}

	if res, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); err == nil {
		log.Printf("Skipping login, current identity:\naccount: %v\nuser: %v\narn: %v", unptr(res.Account), unptr(res.UserId), unptr(res.Arn))
		return nil
	}

	var ssoStartURL, tokenFilePath string
	for _, src := range cfg.ConfigSources {
		if scfg, ok := src.(config.SharedConfig); ok && scfg.SSOSession != nil {
			if scfg.SSOSessionName == "" {
				return errors.New("sso_session must be set")
			}
			if tokenFilePath, err = ssocreds.StandardCachedTokenFilepath(scfg.SSOSessionName); err != nil {
				return err
			}
			ssoStartURL = scfg.SSOSession.SSOStartURL
			break
		}
	}
	if ssoStartURL == "" {
		return errors.New("sso_start_url must be set")
	}

	svc := ssooidc.NewFromConfig(cfg)
	reg, err := svc.RegisterClient(ctx, &ssooidc.RegisterClientInput{
		ClientName: ptr("github.com/artyom/awslogin"),
		ClientType: ptr("public"),
		Scopes:     []string{"sso:account:access"},
	})
	if err != nil {
		return fmt.Errorf("RegisterClient: %w", err)
	}

	deviceAuth, err := svc.StartDeviceAuthorization(ctx, &ssooidc.StartDeviceAuthorizationInput{
		ClientId:     reg.ClientId,
		ClientSecret: reg.ClientSecret,
		StartUrl:     &ssoStartURL,
	})
	if err != nil {
		return fmt.Errorf("StartDeviceAuthorization: %w", err)
	}
	log.Println("Please login at:", *deviceAuth.VerificationUriComplete, codeNotice(*deviceAuth.VerificationUriComplete))

	_ = openBrowser(*deviceAuth.VerificationUriComplete)
	const delay = 5 * time.Second
	log.Printf("polling every %v until the login form is completed", delay)
	createTokenInput := ssooidc.CreateTokenInput{
		ClientId:     reg.ClientId,
		ClientSecret: reg.ClientSecret,
		DeviceCode:   deviceAuth.DeviceCode,
		GrantType:    ptr("urn:ietf:params:oauth:grant-type:device_code"),
	}
	ticker := time.NewTicker(delay)
	var token *ssooidc.CreateTokenOutput
pollLoop:
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if token, err = svc.CreateToken(ctx, &createTokenInput); err == nil {
				break pollLoop
			}
			if strings.Contains(err.Error(), "AuthorizationPendingException") {
				continue
			}
			return fmt.Errorf("CreateToken: %w", err)
		}
	}

	_ = os.MkdirAll(filepath.Dir(tokenFilePath), 0700)
	b, err := json.Marshal(cachedCreds{
		AccessToken:  *token.AccessToken,
		RefreshToken: unptr(token.RefreshToken),
		ClientID:     *reg.ClientId,
		ClientSecret: *reg.ClientSecret,
		ExpiresAt:    time.Now().Add(time.Second * time.Duration(token.ExpiresIn)).UTC(),
	})
	if err != nil {
		return err
	}
	return os.WriteFile(tokenFilePath, b, 0600)
}

func ptr[T any](v T) *T { return &v }
func unptr[T any](v *T) T {
	var zero T
	if v == nil {
		return zero
	}
	return *v
}

// from https://github.com/aws/aws-sdk-go-v2/blob/fe7486fa32d029fc295c3146b3348cfd8ea7a9e7/credentials/ssocreds/sso_cached_token.go#L43C1-L50C2
type cachedCreds struct {
	AccessToken string    `json:"accessToken,omitempty"`
	ExpiresAt   time.Time `json:"expiresAt,omitzero"`

	RefreshToken string `json:"refreshToken,omitempty"`
	ClientID     string `json:"clientId,omitempty"`
	ClientSecret string `json:"clientSecret,omitempty"`
}

func openBrowser(url string) error {
	if !strings.HasPrefix(url, "https://") {
		return fmt.Errorf("suspicious url, expected https:// one: %s", url)
	}
	var openCmd string
	switch runtime.GOOS {
	case "darwin":
		openCmd = "open"
	case "linux", "freebsd":
		openCmd = "xdg-open"
	case "windows":
		openCmd = "explorer.exe"
	default:
		return fmt.Errorf("don't know how to open %q on %s", url, runtime.GOOS)
	}
	return exec.Command(openCmd, url).Run()
}

func codeNotice(s string) string {
	if code := extractCode(s); code != "" {
		return "(make sure the code on the page is \033[7m" + code + "\033[0m)"
	}
	return ""
}

func extractCode(s string) string {
	// https://org.awsapps.com/start/#/device?user_code=ABCD-1234
	u, err := url.Parse(s)
	if err != nil {
		return ""
	}
	if u, err = url.Parse(u.Fragment); err != nil {
		return ""
	}
	return u.Query().Get("user_code")
}
