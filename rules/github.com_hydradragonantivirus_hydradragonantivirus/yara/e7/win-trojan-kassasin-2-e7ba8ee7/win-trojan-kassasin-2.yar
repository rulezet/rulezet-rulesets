rule Win_Trojan_Kassasin_2
{
strings:
	$a0 = { c450b0f086e0cd210bc07452bf611e4ffc9075fb1e }


condition:
	$a0
}