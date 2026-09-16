rule Win_Trojan_Small_4411
{
strings:
	$a0 = { 56575355e810000000e820000000e8fa }


condition:
	$a0
}