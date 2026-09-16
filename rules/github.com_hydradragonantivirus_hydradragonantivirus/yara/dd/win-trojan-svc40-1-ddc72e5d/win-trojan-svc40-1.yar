rule Win_Trojan_SVC40_1
{
strings:
	$a0 = { 0607b80049cd21724db80048bbffff }


condition:
	$a0
}