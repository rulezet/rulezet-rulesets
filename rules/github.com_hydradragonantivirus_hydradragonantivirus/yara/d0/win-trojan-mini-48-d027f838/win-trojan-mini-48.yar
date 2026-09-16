rule Win_Trojan_Mini_48
{
strings:
	$a0 = { 40ba0001b99a01cd21e80200c37bbe03018bfe8a268602b96401ac32c4aae2fac3 }


condition:
	$a0
}