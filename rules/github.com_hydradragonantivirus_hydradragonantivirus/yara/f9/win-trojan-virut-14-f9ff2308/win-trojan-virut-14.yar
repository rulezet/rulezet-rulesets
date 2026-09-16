rule Win_Trojan_Virut_14
{
strings:
	$a0 = { e800000000558b5c24088b6c2404816c2404 }


condition:
	$a0
}