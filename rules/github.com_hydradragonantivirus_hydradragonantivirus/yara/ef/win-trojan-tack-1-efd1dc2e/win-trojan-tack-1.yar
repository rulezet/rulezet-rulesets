rule Win_Trojan_Tack_1
{
strings:
	$a0 = { 050001a33e02c7064002ffe0c606420223b4408b1e35 }


condition:
	$a0
}