rule Win_Trojan_Small_1458
{
strings:
	$a0 = { 68e027001057ffd685c05959750e68c427001057ffd685c059597407 }


condition:
	$a0
}