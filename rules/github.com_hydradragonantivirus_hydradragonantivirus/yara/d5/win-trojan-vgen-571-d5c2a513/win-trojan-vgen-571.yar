rule Win_Trojan_VGEN_571
{
strings:
	$a0 = { e800005d81ed34011e06eb0290e9fab8881350584c4c5b3bc37401f4fb33c08ec0be0400bf0c00a5 }


condition:
	$a0
}