rule Win_Trojan_Sality_1061
{
strings:
	$a0 = { 6087c086c534??ffc?f6c? }


condition:
	$a0
}