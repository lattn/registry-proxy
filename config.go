package main

import (
	"fmt"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

type Config struct {
	Listen       string             `json:"listen"`
	SecurityKey  string             `json:"security_key"`
	LocalAuth    []LocalAuthAccount `json:"local_auth"`
	RegistryURL  string             `json:"registry_url"`
	ImagePrefix  string             `json:"image_prefix"`
	RegistryAuth Credentials        `json:"registry_auth"`
}

type LocalAuthAccount struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	Images   []string `json:"images"`
}

type Credentials struct {
	Username string
	Password string
}

func LoadConfig() (Config, error) {
	v := viper.New()
	v.SetConfigName("config")
	v.AddConfigPath(".")
	err := v.ReadInConfig()
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	err = v.Unmarshal(&cfg, func(config *mapstructure.DecoderConfig) {
		config.TagName = "json"
	})
	if err != nil {
		return Config{}, err
	}
	cfg.RegistryURL = strings.TrimRight(strings.TrimSpace(cfg.RegistryURL), "/")
	cfg.ImagePrefix = normalizeRepositoryPath(cfg.ImagePrefix)
	for i := range cfg.LocalAuth {
		cfg.LocalAuth[i].Images = normalizeRepositories(cfg.LocalAuth[i].Images)
	}
	if err := validateLocalAuthAccounts(cfg.ImagePrefix, cfg.LocalAuth); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func normalizeRepositories(images []string) []string {
	for i := range images {
		images[i] = normalizeRepositoryPath(images[i])
	}
	return images
}

func normalizeRepositoryPath(path string) string {
	return strings.Trim(strings.TrimSpace(path), "/")
}

func validateLocalAuthAccounts(imagePrefix string, accounts []LocalAuthAccount) error {
	if imagePrefix == "" {
		return fmt.Errorf("image prefix is required")
	}
	if !isSafeRepositoryPath(imagePrefix) {
		return fmt.Errorf("invalid image prefix %q", imagePrefix)
	}
	if len(accounts) == 0 {
		return fmt.Errorf("at least one local auth account is required")
	}

	seenUsers := make(map[string]struct{}, len(accounts))
	for _, account := range accounts {
		if account.Username == "" {
			return fmt.Errorf("local auth username is required")
		}
		if account.Password == "" {
			return fmt.Errorf("local auth password is required for %q", account.Username)
		}
		if _, ok := seenUsers[account.Username]; ok {
			return fmt.Errorf("duplicate local auth username %q", account.Username)
		}
		seenUsers[account.Username] = struct{}{}
		if len(account.Images) == 0 {
			return fmt.Errorf("at least one image is required for %q", account.Username)
		}
		if err := validateImageAllowlist(imagePrefix, account.Images); err != nil {
			return fmt.Errorf("local auth account %q: %w", account.Username, err)
		}
	}
	return nil
}

func validateImageAllowlist(imagePrefix string, images []string) error {
	seen := make(map[string]struct{}, len(images))
	for _, image := range images {
		if image == "" {
			return fmt.Errorf("image name is required")
		}
		if !isSafeRepositoryPath(image) {
			return fmt.Errorf("invalid image name %q", image)
		}
		if _, ok := seen[image]; ok {
			return fmt.Errorf("duplicate image name %q", image)
		}
		seen[image] = struct{}{}

		upstream := imagePrefix + "/" + image
		if !isSafeRepositoryPath(upstream) {
			return fmt.Errorf("invalid upstream image name %q", upstream)
		}
	}
	return nil
}
