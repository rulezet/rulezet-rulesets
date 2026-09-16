rule Win_Trojan_Havoc_3
{
strings:
	$a0 = { 89907ca99d4ed190eca9ab6a4d07892fd56a6597 }


condition:
	$a0
}