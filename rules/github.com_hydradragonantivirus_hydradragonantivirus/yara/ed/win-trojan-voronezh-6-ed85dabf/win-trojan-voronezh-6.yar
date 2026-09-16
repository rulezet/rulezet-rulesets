rule Win_Trojan_Voronezh_6
{
strings:
	$a0 = { 8bf0bf0001fc8a0434bb88054647e2f6b8000150c3 }


condition:
	$a0
}