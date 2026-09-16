rule Win_Trojan_Bifrose_723
{
strings:
	$a0 = { 6870204000e8f0ffffff00000000000030000000400000000000000058f900fb }


condition:
	$a0
}