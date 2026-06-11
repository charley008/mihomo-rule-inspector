package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
)

func main() {
	const size = 256
	img := image.NewRGBA(image.Rect(0, 0, size, size))

	bg1 := color.RGBA{10, 18, 28, 255}
	bg2 := color.RGBA{22, 54, 76, 255}
	for y := 0; y < size; y++ {
		t := float64(y) / float64(size-1)
		row := mix(bg1, bg2, t)
		for x := 0; x < size; x++ {
			img.SetRGBA(x, y, row)
		}
	}

	fillRoundedRect(img, 8, 8, 240, 240, 52, color.RGBA{12, 20, 31, 255})
	drawGlowCircle(img, 88, 86, 84, color.RGBA{59, 130, 246, 52})
	drawGlowCircle(img, 172, 168, 56, color.RGBA{16, 185, 129, 40})
	strokeRoundedRect(img, 8, 8, 240, 240, 52, 3, color.RGBA{64, 92, 120, 255})

	route := []image.Point{
		{64, 154},
		{108, 114},
		{146, 130},
		{184, 92},
	}
	for i := 0; i < len(route)-1; i++ {
		drawThickLine(img, route[i], route[i+1], 14, color.RGBA{95, 210, 255, 255})
	}
	for _, p := range route {
		fillCircle(img, p.X, p.Y, 10, color.RGBA{245, 250, 255, 255})
		fillCircle(img, p.X, p.Y, 5, color.RGBA{59, 130, 246, 255})
	}

	strokeCircle(img, 134, 134, 42, 10, color.RGBA{244, 247, 250, 255})
	drawThickLine(img, image.Point{166, 166}, image.Point{208, 208}, 10, color.RGBA{244, 247, 250, 255})
	drawThickLine(img, image.Point{114, 142}, image.Point{132, 126}, 5, color.RGBA{143, 214, 255, 255})
	drawThickLine(img, image.Point{132, 126}, image.Point{150, 134}, 5, color.RGBA{143, 214, 255, 255})

	mustMkdir("assets")
	mustMkdir("web")
	writePNG("assets/appicon.png", img)
	writeICO("assets/appicon.ico", img)
	copyFile("assets/appicon.ico", "web/favicon.ico")
}

func mix(a, b color.RGBA, t float64) color.RGBA {
	return color.RGBA{
		R: uint8(float64(a.R)*(1-t) + float64(b.R)*t),
		G: uint8(float64(a.G)*(1-t) + float64(b.G)*t),
		B: uint8(float64(a.B)*(1-t) + float64(b.B)*t),
		A: 255,
	}
}

func mustMkdir(path string) {
	if err := os.MkdirAll(path, 0o755); err != nil {
		panic(err)
	}
}

func writePNG(path string, img image.Image) {
	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		panic(err)
	}
}

func writeICO(path string, img image.Image) {
	var pngBuf bytes.Buffer
	if err := png.Encode(&pngBuf, img); err != nil {
		panic(err)
	}
	pngBytes := pngBuf.Bytes()

	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	must(binary.Write(f, binary.LittleEndian, uint16(0)))
	must(binary.Write(f, binary.LittleEndian, uint16(1)))
	must(binary.Write(f, binary.LittleEndian, uint16(1)))
	must(binary.Write(f, binary.LittleEndian, uint8(0)))
	must(binary.Write(f, binary.LittleEndian, uint8(0)))
	must(binary.Write(f, binary.LittleEndian, uint8(0)))
	must(binary.Write(f, binary.LittleEndian, uint8(0)))
	must(binary.Write(f, binary.LittleEndian, uint16(1)))
	must(binary.Write(f, binary.LittleEndian, uint16(32)))
	must(binary.Write(f, binary.LittleEndian, uint32(len(pngBytes))))
	must(binary.Write(f, binary.LittleEndian, uint32(22)))
	if _, err := f.Write(pngBytes); err != nil {
		panic(err)
	}
}

func copyFile(src, dst string) {
	data, err := os.ReadFile(src)
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		panic(err)
	}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func fillRoundedRect(img *image.RGBA, x, y, w, h, r int, c color.RGBA) {
	for py := y; py < y+h; py++ {
		for px := x; px < x+w; px++ {
			if insideRoundedRect(px, py, x, y, w, h, r) {
				img.SetRGBA(px, py, c)
			}
		}
	}
}

func strokeRoundedRect(img *image.RGBA, x, y, w, h, r, thickness int, c color.RGBA) {
	for py := y - thickness; py < y+h+thickness; py++ {
		for px := x - thickness; px < x+w+thickness; px++ {
			outer := insideRoundedRect(px, py, x, y, w, h, r)
			inner := insideRoundedRect(px, py, x+thickness, y+thickness, w-2*thickness, h-2*thickness, max(r-thickness, 0))
			if outer && !inner {
				img.SetRGBA(px, py, c)
			}
		}
	}
}

func insideRoundedRect(px, py, x, y, w, h, r int) bool {
	if px < x || py < y || px >= x+w || py >= y+h {
		return false
	}
	if r <= 0 {
		return true
	}
	left := x + r
	right := x + w - r - 1
	top := y + r
	bottom := y + h - r - 1
	if px >= left && px <= right {
		return true
	}
	if py >= top && py <= bottom {
		return true
	}

	corners := []image.Point{
		{left, top},
		{right, top},
		{left, bottom},
		{right, bottom},
	}
	for _, cpt := range corners {
		dx := px - cpt.X
		dy := py - cpt.Y
		if dx*dx+dy*dy <= r*r {
			return true
		}
	}
	return false
}

func drawGlowCircle(img *image.RGBA, cx, cy, r int, c color.RGBA) {
	for y := cy - r; y <= cy+r; y++ {
		for x := cx - r; x <= cx+r; x++ {
			dx := x - cx
			dy := y - cy
			dist := math.Sqrt(float64(dx*dx + dy*dy))
			if dist <= float64(r) {
				alpha := float64(c.A) * (1 - dist/float64(r))
				blend(img, x, y, color.RGBA{c.R, c.G, c.B, uint8(alpha)})
			}
		}
	}
}

func fillCircle(img *image.RGBA, cx, cy, r int, c color.RGBA) {
	for y := cy - r; y <= cy+r; y++ {
		for x := cx - r; x <= cx+r; x++ {
			dx := x - cx
			dy := y - cy
			if dx*dx+dy*dy <= r*r {
				img.SetRGBA(x, y, c)
			}
		}
	}
}

func strokeCircle(img *image.RGBA, cx, cy, r, thickness int, c color.RGBA) {
	outer := r
	inner := max(r-thickness, 0)
	for y := cy - outer; y <= cy+outer; y++ {
		for x := cx - outer; x <= cx+outer; x++ {
			dx := x - cx
			dy := y - cy
			d2 := dx*dx + dy*dy
			if d2 <= outer*outer && d2 >= inner*inner {
				img.SetRGBA(x, y, c)
			}
		}
	}
}

func drawThickLine(img *image.RGBA, a, b image.Point, thickness int, c color.RGBA) {
	steps := int(math.Max(math.Abs(float64(b.X-a.X)), math.Abs(float64(b.Y-a.Y))))
	if steps == 0 {
		fillCircle(img, a.X, a.Y, thickness/2, c)
		return
	}
	for i := 0; i <= steps; i++ {
		t := float64(i) / float64(steps)
		x := int(math.Round(float64(a.X)*(1-t) + float64(b.X)*t))
		y := int(math.Round(float64(a.Y)*(1-t) + float64(b.Y)*t))
		fillCircle(img, x, y, thickness/2, c)
	}
}

func blend(img *image.RGBA, x, y int, c color.RGBA) {
	if !image.Pt(x, y).In(img.Bounds()) {
		return
	}
	dst := img.RGBAAt(x, y)
	a := float64(c.A) / 255
	na := 1 - a
	img.SetRGBA(x, y, color.RGBA{
		R: uint8(float64(c.R)*a + float64(dst.R)*na),
		G: uint8(float64(c.G)*a + float64(dst.G)*na),
		B: uint8(float64(c.B)*a + float64(dst.B)*na),
		A: 255,
	})
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
