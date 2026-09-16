rule Win_Trojan_Stoned_5
{
strings:
	$a0 = { 1372f00e1f0e07bebe03bfbe01b94202f3a4b8010331dbfec1cd13ebd6 }


condition:
	$a0
}