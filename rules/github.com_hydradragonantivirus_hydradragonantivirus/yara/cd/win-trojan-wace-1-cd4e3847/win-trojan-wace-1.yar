rule Win_Trojan_Wace_1
{
strings:
	$a0 = { 558bec83c4d05356578d75fc8b442430250000ffff81384d5a900074072d00100000ebf1 }


condition:
	$a0
}