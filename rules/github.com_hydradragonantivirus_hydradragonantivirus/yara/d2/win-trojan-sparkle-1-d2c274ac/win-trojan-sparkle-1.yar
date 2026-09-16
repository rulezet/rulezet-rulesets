rule Win_Trojan_Sparkle_1
{
strings:
	$a0 = { 5d81ed0901b2008d9e1c01b9ab02301743e2fb }


condition:
	$a0
}