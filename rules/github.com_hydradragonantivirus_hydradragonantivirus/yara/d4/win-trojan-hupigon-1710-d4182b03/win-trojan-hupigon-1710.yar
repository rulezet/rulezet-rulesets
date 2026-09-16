rule Win_Trojan_Hupigon_1710
{
strings:
	$a0 = { 6801?05?00680b104000c3c3ed475bddef841f3c }


condition:
	$a0
}