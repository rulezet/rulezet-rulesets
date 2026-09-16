rule Win_Trojan_Dumador_52
{
strings:
	$a0 = { 685802000059[0-6]80363046e2fac3 }


condition:
	$a0
}