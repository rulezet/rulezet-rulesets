rule Win_Trojan_Chest_1
{
strings:
	$a0 = { 3f009a730020005589e581ec0001bf7d001e578dbe00ff165731c0509a5b083f009a9d063f00bf7d001e57b801 }


condition:
	$a0
}