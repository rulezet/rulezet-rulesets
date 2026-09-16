rule Win_Trojan_Pakes_996
{
strings:
	$a0 = { 60bf0030400057e8??ffffff85c0740261c3fe0757e8??fffffffe0f85c074f0 }


condition:
	$a0
}