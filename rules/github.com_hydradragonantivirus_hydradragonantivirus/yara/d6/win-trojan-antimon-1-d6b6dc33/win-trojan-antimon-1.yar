rule Win_Trojan_Antimon_1
{
strings:
	$a0 = { 5052b419cd218ad0b40ecd213c0472 }


condition:
	$a0
}