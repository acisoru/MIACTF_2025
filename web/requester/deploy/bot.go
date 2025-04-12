package main

import (
	"fmt"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"log"
)

func startTgBot() {
	cfg := GetConfig()

	botToken := cfg.TgBotToken

	bot, err := tgbotapi.NewBotAPI(botToken)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Telegram bot is running...")

	updateConfig := tgbotapi.NewUpdate(0)
	updateConfig.Timeout = 60

	updates := bot.GetUpdatesChan(updateConfig)

	for update := range updates {
		if update.Message == nil {
			continue
		}

		if update.Message.Chat.ID == int64(cfg.AdminUserId) {
			token, err := generateJWT(int(update.Message.Chat.ID))
			if err != nil {
				log.Printf("Failed to generate JWT token: %v", err)
				continue
			}
			bot.Send(tgbotapi.NewMessage(update.Message.Chat.ID, fmt.Sprintf("Your token: %s", token)))
		} else {
			bot.Send(tgbotapi.NewMessage(update.Message.Chat.ID, "You are not authorized"))
		}
	}
}
