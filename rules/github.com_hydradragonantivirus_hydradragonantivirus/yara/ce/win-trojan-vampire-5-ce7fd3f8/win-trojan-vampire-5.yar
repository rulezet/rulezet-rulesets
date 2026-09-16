rule Win_Trojan_Vampire_5
{
strings:
	$a0 = { 55000000030001001a030000840e0000060000001a03 }


condition:
	$a0
}