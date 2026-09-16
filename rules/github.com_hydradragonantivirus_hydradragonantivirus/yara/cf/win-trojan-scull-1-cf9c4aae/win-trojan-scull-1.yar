rule Win_Trojan_Scull_1
{
strings:
	$a0 = { 02beff018a273224f6d488274b4e81fb37017df0c3 }


condition:
	$a0
}