rule Win_Trojan_Tony_3
{
strings:
	$a0 = { 258bd3061fcd210e1fb81325ba87 }


condition:
	$a0
}