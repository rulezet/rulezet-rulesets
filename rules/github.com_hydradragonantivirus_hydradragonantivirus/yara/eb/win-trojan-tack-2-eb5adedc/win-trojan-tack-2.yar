rule Win_Trojan_Tack_2
{
strings:
	$a0 = { 050001a34702c7064902ffe0c6064b0223b4408b1e3e }


condition:
	$a0
}