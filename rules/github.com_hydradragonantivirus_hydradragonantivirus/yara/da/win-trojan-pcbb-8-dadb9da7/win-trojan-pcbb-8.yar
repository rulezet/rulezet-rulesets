rule Win_Trojan_PCBB_8
{
strings:
	$a0 = { 8bdce80000368147fe0e005b438077ff5ae2f9 }


condition:
	$a0
}