rule Win_Trojan_Perelett_1
{
strings:
	$a0 = { e8000000005de8e80300006a45598db5 }


condition:
	$a0
}