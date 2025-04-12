package main

import (
	"arrows/captcha"
	"encoding/base64"
	"fmt"
	"github.com/google/uuid"
	"log"
	"net"
	"os"
	"strings"
)

const (
	FLAG           = "miactf{up_up_down_d0wn_l3ft_right_left_r1ght_s0lved_cap7cha_g3t_th3_fl4g}"
	TOTAL_CAPTCHAS = 1000
	WIN_THRESHOLD  = 80.0
	helloTmlpt     = "Hey, anon! Solve the captcha, get a flag.\n" +
		"You will receive an image in base64, in response you need to send one of the following answers: UP, DOWN, RIGHT, LEFT\n" +
		"Total captchas: %d\nRequired accuracy: %0.1f%%\n\nAttempt UUID: %s\n" +
		"\nPress [ENTER] to start..."
)

func main() {
	startServer(":9999")
}

func startServer(addr string) {
	log.Println("Listening on", addr)

	ln, _ := net.Listen("tcp", addr)
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}

		go NewHandler(conn).handle(conn)
	}
}

type Handler struct {
	UUID string
	conn net.Conn
	l    *log.Logger
}

func NewHandler(conn net.Conn) *Handler {
	UUID := uuid.NewString()
	return &Handler{
		UUID: UUID,
		conn: conn,
		l:    log.New(os.Stdout, fmt.Sprintf("[%s] ", UUID), log.LstdFlags|log.Lmicroseconds),
	}
}

func (h *Handler) handle(conn net.Conn) {
	defer conn.Close()
	defer h.l.Println("Closed!")
	h.l.Println("Started!")

	_, err := h.prompt(fmt.Sprintf(helloTmlpt, TOTAL_CAPTCHAS, WIN_THRESHOLD, h.UUID))
	if err != nil {
		h.l.Printf("Error sending hello: %v", err)
		return
	}

	cfg := captcha.CaptchaConfig{
		EnableNoise:       true,
		EnableColorJitter: true,
		EnableWarp:        true,
		EnableRandomLines: true,
	}

	correct := 0
	acc := 0.0
	for i := 0; i < TOTAL_CAPTCHAS; i++ {
		imageBytes, dir := captcha.GenerateArrowImage(300, 300, cfg)

		b64 := base64.StdEncoding.EncodeToString(imageBytes)
		_, err := conn.Write([]byte(b64 + "\n"))
		if err != nil {
			h.l.Printf("Error sending image: %v", err)
			return
		}

		answer, err := h.prompt(fmt.Sprintf("[n=%d, acc=%0.1f%%] Direction: ", i+1, acc))
		if err != nil {
			h.l.Printf("Error sending answer: %v", err)
			return
		}
		if answer == dir {
			correct++
		}
		acc = (float64(correct) / (float64(i + 1))) * 100
	}

	if _, err = h.conn.Write([]byte(fmt.Sprintf("Final accuracy: %0.1f%%\n\n", acc))); err != nil {
		h.l.Printf("Error sending final accuracy: %v", err)
		return
	}

	if acc < WIN_THRESHOLD {
		h.conn.Write([]byte("Low accuracy anon((\ngl next time!\nbye.\n"))
		return
	}
	h.conn.Write([]byte(fmt.Sprintf("Great work anon!\nHere is your flag: %s\n", FLAG)))
}

func (h *Handler) prompt(promptMsg string) (string, error) {
	_, err := h.conn.Write([]byte(promptMsg))
	if err != nil {
		return "", err
	}

	bytes := make([]byte, 64)
	_, err = h.conn.Read(bytes)
	if err != nil {
		return "", err
	}

	firstNullInd := 0
	for i, b := range bytes {
		if b == 0x00 {
			firstNullInd = i
			break
		}
	}
	answer := string(bytes[:firstNullInd])

	return strings.TrimSpace(answer), nil
}
