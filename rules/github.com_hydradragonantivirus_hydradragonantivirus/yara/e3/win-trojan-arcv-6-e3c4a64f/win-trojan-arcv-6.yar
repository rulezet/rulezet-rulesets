rule Win_Trojan_ARCV_6
{
strings:
	$a0 = { e80000b913015e81ee21028dbc0b0180355147e2fac3 }


condition:
	$a0
}