package captcha

import (
	"bytes"
	"github.com/fogleman/gg"
	"image/color"
	"image/jpeg"
	"log"
	"math"
	"math/rand"
)

// CaptchaConfig описывает, какие фильтры включены
type CaptchaConfig struct {
	EnableNoise       bool // Добавлять шум к фону
	EnableColorJitter bool // Изменять яркость/контраст/цвет
	EnableWarp        bool // Делать перспективное искажение
	EnableRandomLines bool
}

// Directions - возможные направления
var Directions = []string{"UP", "RIGHT", "DOWN", "LEFT"}

// GenerateArrowImage генерирует PNG со стрелкой, кодирует её в base64 и возвращает
// вместе с информацией о направлении
func GenerateArrowImage(width, height int, cfg CaptchaConfig) ([]byte, string) {
	dc := gg.NewContext(width, height)

	// 1. Рисуем фон
	bgColor := drawBackground(dc, cfg)

	// 2. Определяем направление
	direction := Directions[rand.Intn(len(Directions))]

	// 3. Рисуем стрелку
	drawArrow(dc, direction, bgColor)

	// 4. Применяем эффект Warp (если нужно)
	//    В fogleman/gg нет "из коробки" готового перспективного искажения.
	//    Ниже — упрощённый warp (волна).
	if cfg.EnableWarp {
		applyWaveWarp(dc)
	}

	// 5. Применяем цветовую "штриховку" (brightness/contrast и т.п.)
	if cfg.EnableColorJitter {
		applyColorJitter(dc)
	}

	if cfg.EnableRandomLines {
		applyRandomLines(dc, rand.Intn(70)+30)
	}

	// 6. Кодируем в PNG -> base64
	img := dc.Image()
	var buf bytes.Buffer
	err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 90})
	if err != nil {
		log.Fatal(err)
	}
	return buf.Bytes(), direction
}

// drawBackground рисует фон: случайный цвет и (опционально) шум
func drawBackground(dc *gg.Context, cfg CaptchaConfig) color.Color {
	w := dc.Width()
	h := dc.Height()

	// Заливаем фон случайным цветом
	bg := randomColor()
	dc.SetColor(bg)
	dc.Clear()

	// Если включен шум - рисуем кучу полупрозрачных точек
	if cfg.EnableNoise {
		for i := 0; i < 1000; i++ {
			x := rand.Float64() * float64(w)
			y := rand.Float64() * float64(h)
			dc.SetRGBA(rand.Float64(), rand.Float64(), rand.Float64(), 0.2)
			dc.DrawPoint(x, y, rand.Float64()*2.0+1.0)
			dc.Fill()
		}
	}

	return bg
}

// drawArrow рисует стрелку в случайном положении (или центре)
func drawArrow(dc *gg.Context, direction string, bgColor color.Color) {
	w := dc.Width()
	h := dc.Height()

	centerX := float64(w) / 2
	centerY := float64(h) / 2
	arrowLen := float64(w) * 0.3

	// Большой рандом для смещения центра
	switch direction {
	case "UP", "DOWN":
		bigOffsetMax := rand.Float64() * (float64(dc.Width()) - centerX) * 0.85
		centerX += bigOffsetMax * float64(randomSign())
	case "LEFT", "RIGHT":
		bigOffsetMax := rand.Float64() * (float64(dc.Height()) - centerY) * 0.85
		centerY += bigOffsetMax * float64(randomSign())
	}

	// Небольшой рандом для смещения центра
	offsetX := rand.Float64()*40 - 20
	offsetY := rand.Float64()*40 - 20
	centerX += offsetX
	centerY += offsetY

	// Толщина стрелки
	thickness := float64(rand.Intn(6) + 5)

	dc.SetLineWidth(thickness)

	arrowColor := contrastingColor(bgColor.RGBA())
	dc.SetColor(arrowColor)

	var endX, endY float64

	switch direction {
	case "UP":
		endX, endY = centerX, centerY-arrowLen
	case "RIGHT":
		endX, endY = centerX+arrowLen, centerY
	case "DOWN":
		endX, endY = centerX, centerY+arrowLen
	case "LEFT":
		endX, endY = centerX-arrowLen, centerY
	}

	// Рисуем линию
	dc.DrawLine(centerX, centerY, endX, endY)
	dc.Stroke()

	// Рисуем "треугольник" наконечника
	arrowHeadSize := thickness * 2
	dc.SetColor(arrowColor)
	switch direction {
	case "UP":
		dc.MoveTo(endX, endY-arrowHeadSize)
	case "RIGHT":
		dc.LineTo(endX+arrowHeadSize, endY)
	case "DOWN":
		dc.LineTo(endX, endY+arrowHeadSize)
	case "LEFT":
		dc.LineTo(endX-arrowHeadSize, endY)
	}

	switch direction {
	case "UP":
		dc.LineTo(endX-arrowHeadSize, endY+arrowHeadSize)
		dc.LineTo(endX+arrowHeadSize, endY+arrowHeadSize)
	case "RIGHT":
		dc.LineTo(endX-arrowHeadSize, endY-arrowHeadSize)
		dc.LineTo(endX-arrowHeadSize, endY+arrowHeadSize)
	case "DOWN":
		dc.LineTo(endX-arrowHeadSize, endY-arrowHeadSize)
		dc.LineTo(endX+arrowHeadSize, endY-arrowHeadSize)
	case "LEFT":
		dc.LineTo(endX+arrowHeadSize, endY-arrowHeadSize)
		dc.LineTo(endX+arrowHeadSize, endY+arrowHeadSize)
	}
	dc.ClosePath()
	dc.Fill()
}

// applyWaveWarp — простой "волновой" эффект (искажение по синусу)
func applyWaveWarp(dc *gg.Context) {
	w := dc.Width()
	h := dc.Height()

	// Считываем текущее изображение в пиксельный массив
	srcImg := dc.Image()
	dst := gg.NewContext(w, h)

	amplitude := float64(rand.Intn(4) + 5) // высота волны
	frequency := float64(rand.Intn(4))     // частота волны

	for y := 0; y < h; y++ {
		// Вычисляем смещение по оси X
		shiftX := int(amplitude * math.Sin(float64(y)/10.0*frequency))
		for x := 0; x < w; x++ {
			srcX := x + shiftX
			srcY := y
			if srcX >= 0 && srcX < w {
				c := srcImg.At(srcX, srcY)
				dst.SetColor(c)
				dst.SetPixel(x, y)
			}
		}
	}
	dc.DrawImage(dst.Image(), 0, 0)
}

// applyColorJitter — простые изменения яркости/контраста/цвета
func applyColorJitter(dc *gg.Context) {
	w := dc.Width()
	h := dc.Height()
	img := dc.Image()
	dst := gg.NewContext(w, h)

	// Например, рандомный коэф. яркости в диапазоне [0.7 .. 1.3]
	brightness := 0.7 + rand.Float64()*0.6
	// Рандомный коэф. контраста [0.8 .. 1.2]
	contrast := 0.8 + rand.Float64()*0.4

	// Формула для контраста/яркости:
	// newColor = ((oldColor - 128) * contrast + 128)*brightness
	// (но в [0..255])
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			r, g, b, a := img.At(x, y).RGBA()
			// RGBA в Go возвращает значение в 16 бит на канал [0..65535].
			// Преобразуем в [0..255].
			rr := float64(r >> 8)
			gg := float64(g >> 8)
			bb := float64(b >> 8)

			// Применяем контраст
			rr = ((rr - 128) * contrast) + 128
			gg = ((gg - 128) * contrast) + 128
			bb = ((bb - 128) * contrast) + 128

			// Применяем яркость
			rr *= brightness
			gg *= brightness
			bb *= brightness

			// Обрезаем в [0..255]
			if rr < 0 {
				rr = 0
			} else if rr > 255 {
				rr = 255
			}
			if gg < 0 {
				gg = 0
			} else if gg > 255 {
				gg = 255
			}
			if bb < 0 {
				bb = 0
			} else if bb > 255 {
				bb = 255
			}

			dst.SetRGBA255(int(rr), int(gg), int(bb), int(a>>8))
			dst.SetPixel(x, y)
		}
	}
	dc.DrawImage(dst.Image(), 0, 0)
}

// applyRandomLines - рисует рандомные линии
func applyRandomLines(dc *gg.Context, count int) {
	w := float64(dc.Width())
	h := float64(dc.Height())

	dc.SetRGBA(rand.Float64(), rand.Float64(), rand.Float64(), 0.6)

	for i := 0; i < count; i++ {
		x1 := rand.Float64() * w
		y1 := rand.Float64() * h
		x2 := rand.Float64() * w
		y2 := rand.Float64() * h

		dc.DrawLine(x1, y1, x2, y2)
		dc.SetLineWidth(rand.Float64()*3 + 1)
		dc.Stroke()
	}
}

// randomColor - возвращает случайный цвет
func randomColor() color.Color {
	return color.RGBA{
		R: uint8(rand.Intn(256)),
		G: uint8(rand.Intn(256)),
		B: uint8(rand.Intn(256)),
		A: 255,
	}
}

// randomSign - возвращает инт с рандомным знаком
func randomSign() int {
	if rand.Intn(2) == 0 {
		return -1
	}
	return 1
}

// contrastingColor - генерит контрастные переданному цвету цвет
func contrastingColor(r, g, b, _ uint32) color.RGBA {
	bgBrightness := perceivedBrightness(r, g, b)

	var targetBrightness float64
	if bgBrightness > 128 {
		targetBrightness = 30 + rand.Float64()*10
	} else {
		targetBrightness = 220 + rand.Float64()*10
	}

	return generateColorWithBrightness(targetBrightness)
}

func perceivedBrightness(r, g, b uint32) float64 {
	return 0.299*float64(r) + 0.587*float64(g) + 0.114*float64(b)
}

func generateColorWithBrightness(targetBrightness float64) color.RGBA {
	for {
		r := rand.Intn(256)
		g := rand.Intn(256)
		b := rand.Intn(256)
		brightness := perceivedBrightness(uint32(r), uint32(g), uint32(b))

		if (targetBrightness-10) <= brightness && brightness <= (targetBrightness+10) {
			return color.RGBA{R: uint8(r), G: uint8(g), B: uint8(b), A: 255}
		}
	}
}
