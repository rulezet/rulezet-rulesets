rule Win_Trojan_Nuclear_3
{
strings:
	$a0 = { 060055ec01000900ffff260500005101000003000000e014 }


condition:
	$a0
}