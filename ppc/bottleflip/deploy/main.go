package main

import (
	"bufio"
	"fmt"
	"github.com/google/uuid"
	"log"
	"math"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
)

const (
	LEVELS            = 1000
	FLAG              = "miactf{mlmlml_ihateml_iloveml_ihateml_iloveml_hh77}"
	MIN_WIN_RATE      = 85
	CORRECT_THRESHOLD = 2
)

func main() {
	startServer(":8080")
}

func startServer(addr string) {
	log.Println("Listening on", addr)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}

		go NewHandler(conn).handle()
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

func (h *Handler) handle() {
	defer h.conn.Close()

	hello := fmt.Sprintf("Hello, win %d bottle flip challenges with win rate over %d%% and get the flag!\n(correct = perfect angular velocity +- %d)\n\n",
		LEVELS, MIN_WIN_RATE, CORRECT_THRESHOLD)
	if _, err := h.conn.Write([]byte(hello)); err != nil {
		h.l.Printf("Error writing response: %v", err)
		return
	}

	correctLevels := 0
	for i := 0; i < LEVELS; i++ {
		Vb := rand.Float64()*20 + 1
		Vw := rand.Float64() * Vb
		g := rand.Float64()*100 + 1

		correct := calculateAngularSpeed(Vb, Vw, g)

		prompt := fmt.Sprintf("%d. Bottle volume: %0.5fL, Water volume: %0.5fL, Gravity: %0.5fm/s²\nEnter angular velocity: ", i+1, Vb, Vw, g)
		if _, err := h.conn.Write([]byte(prompt)); err != nil {
			h.l.Printf("Error writing prompt: %v", err)
			return
		}

		reader := bufio.NewReader(h.conn)
		response, err := reader.ReadString('\n')
		if err != nil {
			h.l.Printf("Client error: %v", err)
			if _, err := h.conn.Write([]byte("Error reading input. Connection closed.\n")); err != nil {
				h.l.Printf("Error closing connection: %v", err)
			}
			return
		}

		response = strings.TrimSpace(response)
		userAnswer, err := strconv.ParseFloat(response, 64)
		if err != nil {
			h.l.Printf("Invalid input: %s", response)
			if _, err := h.conn.Write([]byte("Invalid input. Please enter a number.\n")); err != nil {
				h.l.Printf("error writing response: %v", err)
				return
			}

			if _, err := h.conn.Write([]byte(fmt.Sprintf("Correct angular velocity was %0.5f\n", correct))); err != nil {
				h.l.Printf("error writing response: %v", err)
				return
			}
			return
		}

		success := false
		if math.Abs(userAnswer-correct) < CORRECT_THRESHOLD {
			success = true
			if _, err := h.conn.Write([]byte("Success! Bottle landed upright!\n")); err != nil {
				h.l.Printf("error writing to connection: %v", err)
				return
			}
			correctLevels++
		} else {
			if _, err := h.conn.Write([]byte("Failed! Bottle fell over.\n")); err != nil {
				h.l.Printf("error writing to connection: %v", err)
			}
		}

		if _, err := h.conn.Write([]byte(fmt.Sprintf("Correct angular velocity was %0.5f\n", correct))); err != nil {
			h.l.Printf("error writing to connection: %v", err)
		}

		h.l.Printf("Challenge: Vb=%0.5f, Vw=%0.5f, g=%0.5f, correct=%0.5f, user=%0.5f, success=%v",
			Vb, Vw, g, correct, userAnswer, success)
	}

	winRate := (correctLevels * 100) / LEVELS
	if winRate >= MIN_WIN_RATE {
		if _, err := h.conn.Write([]byte(fmt.Sprintf("Congratulations! Win rate = %d%%, your flag: %s", winRate, FLAG))); err != nil {
			h.l.Printf("error writing to connection: %v", err)
			return
		}
		return
	}

	if _, err := h.conn.Write([]byte(fmt.Sprintf("Failed! Min win rate =  %d%%, your = %d%%", MIN_WIN_RATE, winRate))); err != nil {
		h.l.Printf("error writing to connection: %v", err)
		return
	}
}

func calculateAngularSpeed(Vb, Vw, g float64) float64 {
	term1 := Vb * Vb * math.Sin(Vw)
	term2 := math.Log(g + 1.0)
	term3 := term1 + term2
	term4 := math.Tanh(Vw * g)
	term5 := term3 * term4
	term6 := term5 / (Vb + 0.1)
	term7 := math.Sqrt(Vw + g)

	return term6 + term7 // окончательный результат
}
