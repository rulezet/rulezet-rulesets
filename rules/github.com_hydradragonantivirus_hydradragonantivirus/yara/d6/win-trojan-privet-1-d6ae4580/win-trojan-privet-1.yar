rule Win_Trojan_Privet_1
{
strings:
	$a0 = { 402e8b1ecc032e8b0e4d040e1fbae203cd21b442b0022e8b1ecc03b90000ba0000cd21b4402e }


condition:
	$a0
}