rule Win_Trojan_Atas_2
{
strings:
	$a0 = { 3f8d968700b90600cd217266b45ab04d39868700740780 }


condition:
	$a0
}