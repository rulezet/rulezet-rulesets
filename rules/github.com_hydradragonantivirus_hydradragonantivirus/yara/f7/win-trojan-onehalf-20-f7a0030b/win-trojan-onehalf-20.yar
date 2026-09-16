rule Win_Trojan_OneHalf_20
{
strings:
	$a0 = { 12b106d3e0ba80008ec0b90c00b8060206cd13b84a0250cb }


condition:
	$a0
}