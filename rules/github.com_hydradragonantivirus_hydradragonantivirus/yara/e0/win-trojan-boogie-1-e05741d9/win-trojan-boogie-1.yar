rule Win_Trojan_Boogie_1
{
strings:
	$a0 = { 010400550001000300ffff452100001e000000030000004521 }


condition:
	$a0
}