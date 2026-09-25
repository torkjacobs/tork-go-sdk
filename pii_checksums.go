package tork

// Check digits for the country registry.
//
// The SDK bundle NAMES twenty algorithms and gives weights and a modulus for
// the eleven that reduce to them; the other nine are marked kind:"custom" and
// carry no specification, so they are ported here by hand from
// landing/lib/pii/checksums.ts -- the single implementation the cloud and the
// country corpus both use. Keeping the arithmetic identical is what makes a
// receipt block from this SDK byte-identical to one from the JS SDK.
//
// Every function is pure: a string in, a bool out. No I/O, no clock.

import (
	"regexp"
	"strings"
)

var nonDigit = regexp.MustCompile(`\D`)

func digitsOf(s string) string {
	return nonDigit.ReplaceAllString(s, "")
}

// modDigits is the remainder of a long decimal digit string modulo m, digit by
// digit, so no value ever exceeds the range of an int.
func modDigits(digits string, m int) int {
	r := 0
	for _, ch := range digits {
		r = (r*10 + int(ch-'0')) % m
	}
	return r
}

func allSameDigit(d string) bool {
	for i := 1; i < len(d); i++ {
		if d[i] != d[0] {
			return false
		}
	}
	return len(d) > 0
}

// Luhn implements ISO/IEC 7812-1 mod-10.
func Luhn(input string) bool {
	d := digitsOf(input)
	if len(d) < 2 {
		return false
	}
	sum := 0
	dbl := false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if dbl {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		dbl = !dbl
	}
	return sum%10 == 0
}

var verhoeffMul = [10][10]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
	{1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
	{2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
	{3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
	{4, 0, 1, 2, 3, 9, 5, 6, 7, 8},
	{5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
	{6, 5, 9, 8, 7, 1, 0, 4, 3, 2},
	{7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
	{8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
	{9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
}

var verhoeffPerm = [8][10]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
	{1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
	{5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
	{8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
	{9, 4, 5, 3, 1, 2, 6, 8, 7, 0},
	{4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
	{2, 7, 9, 3, 8, 0, 6, 4, 1, 5},
	{7, 0, 4, 6, 9, 1, 3, 2, 5, 8},
}

// Verhoeff is the Aadhaar check digit (UIDAI Circular No. 1 of 2018).
func Verhoeff(input string) bool {
	d := digitsOf(input)
	c := 0
	for i := 0; i < len(d); i++ {
		digit := int(d[len(d)-1-i] - '0')
		c = verhoeffMul[c][verhoeffPerm[i%8][digit]]
	}
	return c == 0
}

// AuTfn is the Australian TFN (ATO): weights 1,4,3,7,5,8,6,9,10, sum mod 11 == 0.
func AuTfn(input string) bool {
	d := digitsOf(input)
	if len(d) != 9 {
		return false
	}
	w := []int{1, 4, 3, 7, 5, 8, 6, 9, 10}
	sum := 0
	for i := 0; i < 9; i++ {
		sum += int(d[i]-'0') * w[i]
	}
	return sum%11 == 0
}

// AuAbn is the Australian ABN (ABR): subtract 1 from the first digit, weights
// 10,1,3..19, sum mod 89 == 0.
func AuAbn(input string) bool {
	d := digitsOf(input)
	if len(d) != 11 {
		return false
	}
	w := []int{10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19}
	sum := (int(d[0]-'0') - 1) * w[0]
	for i := 1; i < 11; i++ {
		sum += int(d[i]-'0') * w[i]
	}
	return sum%89 == 0
}

// AuMedicare is the Australian Medicare card number (Services Australia).
func AuMedicare(input string) bool {
	d := digitsOf(input)
	if len(d) < 10 {
		return false
	}
	if !strings.ContainsRune("23456", rune(d[0])) {
		return false
	}
	w := []int{1, 3, 7, 9, 1, 3, 7, 9}
	sum := 0
	for i := 0; i < 8; i++ {
		sum += int(d[i]-'0') * w[i]
	}
	return sum%10 == int(d[8]-'0')
}

// UkNhs is the NHS number (NHS Data Model and Dictionary): weights 10..2,
// check = 11 - (sum mod 11); 11 -> 0; 10 is invalid.
func UkNhs(input string) bool {
	d := digitsOf(input)
	if len(d) != 10 {
		return false
	}
	sum := 0
	for i := 0; i < 9; i++ {
		sum += int(d[i]-'0') * (10 - i)
	}
	check := 11 - (sum % 11)
	if check == 11 {
		check = 0
	}
	if check == 10 {
		return false
	}
	return check == int(d[9]-'0')
}

// BrCpf is the Brazilian CPF (Receita Federal): two sequential mod-11 check digits.
func BrCpf(input string) bool {
	d := digitsOf(input)
	if len(d) != 11 || allSameDigit(d) {
		return false
	}
	calc := func(length int) int {
		sum := 0
		for i := 0; i < length; i++ {
			sum += int(d[i]-'0') * (length + 1 - i)
		}
		r := (sum * 10) % 11
		if r == 10 {
			return 0
		}
		return r
	}
	return calc(9) == int(d[9]-'0') && calc(10) == int(d[10]-'0')
}

// BrCnpj is the Brazilian CNPJ (Receita Federal): two mod-11 check digits with
// different weight vectors per pass.
func BrCnpj(input string) bool {
	d := digitsOf(input)
	if len(d) != 14 || allSameDigit(d) {
		return false
	}
	calc := func(weights []int) int {
		sum := 0
		for i, w := range weights {
			sum += int(d[i]-'0') * w
		}
		r := sum % 11
		if r < 2 {
			return 0
		}
		return 11 - r
	}
	return calc([]int{5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2}) == int(d[12]-'0') &&
		calc([]int{6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2}) == int(d[13]-'0')
}

// JpMyNumber is the Japanese Individual Number (MIC Ordinance No. 85 of 2014).
func JpMyNumber(input string) bool {
	d := digitsOf(input)
	if len(d) != 12 {
		return false
	}
	sum := 0
	for n := 1; n <= 11; n++ {
		p := int(d[11-n] - '0')
		q := n - 5
		if n <= 6 {
			q = n + 1
		}
		sum += p * q
	}
	r := sum % 11
	check := 0
	if r > 1 {
		check = 11 - r
	}
	return check == int(d[11]-'0')
}

var cnResidentIDRe = regexp.MustCompile(`^\d{17}[\dX]$`)

// CnResidentID is the Chinese resident ID (GB 11643-1999): ISO 7064 MOD 11-2
// over 17 digits, with a check character that may be X.
func CnResidentID(input string) bool {
	s := strings.ToUpper(strings.ReplaceAll(input, " ", ""))
	s = strings.ReplaceAll(s, "\t", "")
	if !cnResidentIDRe.MatchString(s) {
		return false
	}
	w := []int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	sum := 0
	for i := 0; i < 17; i++ {
		sum += int(s[i]-'0') * w[i]
	}
	return "10X98765432"[sum%11] == s[17]
}

// KrRrn is the Korean RRN check digit, for numbers issued before 20 Oct 2020.
//
// ADVISORY ONLY, never a gate: numbers issued from 20 Oct 2020 are randomly
// assigned and carry no check digit, so rejecting on this would stop detecting
// every RRN issued since.
func KrRrn(input string) bool {
	d := digitsOf(input)
	if len(d) != 13 {
		return false
	}
	w := []int{2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5}
	sum := 0
	for i := 0; i < 12; i++ {
		sum += int(d[i]-'0') * w[i]
	}
	return (11-(sum%11))%10 == int(d[12]-'0')
}

var sgNricRe = regexp.MustCompile(`^[STFGM]\d{7}[A-Z]$`)

// SgNric is the Singapore NRIC/FIN (ICA): weights 2,7,6,5,4,3,2 and a
// prefix-dependent check-letter table.
func SgNric(input string) bool {
	s := strings.ToUpper(strings.ReplaceAll(input, " ", ""))
	if !sgNricRe.MatchString(s) {
		return false
	}
	w := []int{2, 7, 6, 5, 4, 3, 2}
	sum := 0
	for i := 0; i < 7; i++ {
		sum += int(s[1+i]-'0') * w[i]
	}
	prefix := s[0]
	if prefix == 'T' || prefix == 'G' {
		sum += 4
	}
	if prefix == 'M' {
		sum += 3
	}
	var table string
	switch {
	case prefix == 'S' || prefix == 'T':
		table = "JZIHGFEDCBA"
	case prefix == 'M':
		table = "KLJNPQRTUWX"
	default:
		table = "XWUTRQPNMLK"
	}
	return table[sum%11] == s[8]
}

var cfOdd = map[byte]int{
	'0': 1, '1': 0, '2': 5, '3': 7, '4': 9, '5': 13, '6': 15, '7': 17, '8': 19, '9': 21,
	'A': 1, 'B': 0, 'C': 5, 'D': 7, 'E': 9, 'F': 13, 'G': 15, 'H': 17, 'I': 19, 'J': 21,
	'K': 2, 'L': 4, 'M': 18, 'N': 20, 'O': 11, 'P': 3, 'Q': 6, 'R': 8, 'S': 12, 'T': 14,
	'U': 16, 'V': 10, 'W': 22, 'X': 25, 'Y': 24, 'Z': 23,
}

var cfRe = regexp.MustCompile(`^[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]$`)

// ItCodiceFiscale is the Italian codice fiscale (Agenzia delle Entrate): odd
// and even position character tables, summed mod 26, mapped to a check letter.
func ItCodiceFiscale(input string) bool {
	s := strings.ToUpper(strings.ReplaceAll(input, " ", ""))
	if !cfRe.MatchString(s) {
		return false
	}
	sum := 0
	for i := 0; i < 15; i++ {
		c := s[i]
		if i%2 == 0 {
			sum += cfOdd[c]
		} else if c >= '0' && c <= '9' {
			sum += int(c - '0')
		} else {
			sum += int(c - 'A')
		}
	}
	return byte('A'+(sum%26)) == s[15]
}

var frNirRe = regexp.MustCompile(`^[12]\d{2}\d{2}(\d{2}|2A|2B)\d{3}\d{3}\d{2}$`)

// FrNir is the French NIR (Insee): 97-complement over the 13-digit body, with
// the Corsican 2A/2B department codes mapped to digits first.
func FrNir(input string) bool {
	s := strings.ToUpper(strings.ReplaceAll(input, " ", ""))
	if !frNirRe.MatchString(s) {
		return false
	}
	s = strings.Replace(s, "2A", "19", 1)
	s = strings.Replace(s, "2B", "18", 1)
	body := s[:13]
	key := 0
	for i := 13; i < 15; i++ {
		key = key*10 + int(s[i]-'0')
	}
	return 97-modDigits(body, 97) == key
}

// DeSteuerID is the German Steuer-IdNr (BZSt): ISO 7064 MOD 11,10 over 10 digits.
func DeSteuerID(input string) bool {
	d := digitsOf(input)
	if len(d) != 11 || d[0] == '0' {
		return false
	}
	product := 10
	for i := 0; i < 10; i++ {
		sum := (int(d[i]-'0') + product) % 10
		if sum == 0 {
			sum = 10
		}
		product = (sum * 2) % 11
	}
	check := 11 - product
	if check == 10 {
		check = 0
	}
	return check == int(d[10]-'0')
}

// ThNationalID is the Thai national ID (DOPA): weights 13..2 over 12 digits,
// check = (11 - sum mod 11) mod 10.
func ThNationalID(input string) bool {
	d := digitsOf(input)
	if len(d) != 13 {
		return false
	}
	sum := 0
	for i := 0; i < 12; i++ {
		sum += int(d[i]-'0') * (13 - i)
	}
	return (11-(sum%11))%10 == int(d[12]-'0')
}

// CaSin is the Canadian SIN (Service Canada): Luhn over 9 digits. Advisory --
// the algorithm is community-sourced, not authority-published.
func CaSin(input string) bool { return len(digitsOf(input)) == 9 && Luhn(input) }

// ZaID is the South African ID (SARS PAYE BRS Appendix B 8.3): Luhn over 13 digits.
func ZaID(input string) bool { return len(digitsOf(input)) == 13 && Luhn(input) }

// AeEmiratesID is the UAE Emirates ID (ICP): Luhn over 15 digits starting 784.
// Advisory -- community-sourced.
func AeEmiratesID(input string) bool {
	d := digitsOf(input)
	return len(d) == 15 && strings.HasPrefix(d, "784") && Luhn(d)
}

// SaNationalID is the Saudi national ID / iqama: Luhn over 10 digits starting 1
// or 2. Advisory -- community-sourced.
func SaNationalID(input string) bool {
	d := digitsOf(input)
	return len(d) == 10 && (d[0] == '1' || d[0] == '2') && Luhn(d)
}

// ChecksumFunctions is keyed by the bundle's Checksum field.
var ChecksumFunctions = map[string]func(string) bool{
	"luhn":              Luhn,
	"verhoeff":          Verhoeff,
	"au_tfn":            AuTfn,
	"au_abn":            AuAbn,
	"au_medicare":       AuMedicare,
	"uk_nhs":            UkNhs,
	"br_cpf":            BrCpf,
	"br_cnpj":           BrCnpj,
	"jp_my_number":      JpMyNumber,
	"cn_resident_id":    CnResidentID,
	"kr_rrn":            KrRrn,
	"sg_nric":           SgNric,
	"it_codice_fiscale": ItCodiceFiscale,
	"fr_nir":            FrNir,
	"de_steuer_id":      DeSteuerID,
	"th_national_id":    ThNationalID,
	"ca_sin":            CaSin,
	"za_id":             ZaID,
	"ae_emirates_id":    AeEmiratesID,
	"sa_national_id":    SaNationalID,
}
