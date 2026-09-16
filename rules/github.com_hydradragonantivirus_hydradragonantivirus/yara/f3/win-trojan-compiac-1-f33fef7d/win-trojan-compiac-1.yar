rule Win_Trojan_Compiac_1
{
strings:
	$a0 = { cd2102c07552b802faba4559cd16b402cd1afec5b4 }


condition:
	$a0
}