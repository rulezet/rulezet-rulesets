rule Win_Trojan_Flip_11
{
strings:
	$a0 = { 8ed0bc007cfbb80300e81f0006b8420050b8c007 }


condition:
	$a0
}