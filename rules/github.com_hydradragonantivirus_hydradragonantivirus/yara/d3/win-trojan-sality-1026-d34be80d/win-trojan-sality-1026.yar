rule Win_Trojan_Sality_1026
{
strings:
	$a0 = { 60e8590000008dbd0010400090909068????????033c248bf79068341040009bdbe355db0424 }


condition:
	$a0
}