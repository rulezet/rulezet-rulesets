rule Win_Trojan_Orphan_1
{
strings:
	$a0 = { 6b4fcd1381fb6b4f7430b80102ba8000b901000e07bbae01cd13bfc701c7058d060e1fbf3902 }


condition:
	$a0
}