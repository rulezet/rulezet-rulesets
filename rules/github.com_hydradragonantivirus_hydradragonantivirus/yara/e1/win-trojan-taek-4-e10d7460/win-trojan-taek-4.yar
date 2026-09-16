rule Win_Trojan_Taek_4
{
strings:
	$a0 = { be2900b935062e8a0434572e880446e2f5 }


condition:
	$a0
}