rule Win_Trojan_A2Space_1
{
strings:
	$a0 = { 6035cd2181fb34127403e9c903e90a03505351521e0657 }


condition:
	$a0
}