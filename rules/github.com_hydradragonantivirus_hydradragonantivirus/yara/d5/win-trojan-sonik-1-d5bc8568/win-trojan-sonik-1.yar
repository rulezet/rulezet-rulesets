rule Win_Trojan_Sonik_1
{
strings:
	$a0 = { 8ec02e8c1e88038ed8803e0200907416bb36008a1602 }


condition:
	$a0
}