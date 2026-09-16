rule Win_Trojan_Spectre_2
{
strings:
	$a0 = { 3c2450e8a40f595dc3558bec81ec94005657e86319b80a0050b8050050e8bf195959b8612450e8 }


condition:
	$a0
}