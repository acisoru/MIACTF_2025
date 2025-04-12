package main

import (
	"github.com/ilyakaznacheev/cleanenv"
	"log"
)

type Config struct {
	AdminUserId int    `env:"ADMIN_USER_ID" env-required:"true"`
	TgBotToken  string `env:"TG_BOT_TOKEN" env-required:"true"`
	BotLink     string `env:"BOT_LINK" env-required:"true"`

	initialized bool
}

var config Config

func GetConfig() Config {
	if config.initialized {
		return config
	}

	if err := cleanenv.ReadEnv(&config); err != nil {
		log.Fatal(err)
	}

	return config
}
