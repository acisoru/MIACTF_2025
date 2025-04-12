package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: ./main <pin_code>")
		os.Exit(1)
	}

	pinCode := os.Args[1]

	if pinCode == "65432" {
		fmt.Println("you flag is miactf{spa$1bo_y_obyzateln0__popravly_bag}")
	} else {
		fmt.Println("Invalid pin code")
	}
}
