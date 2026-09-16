rule Win_Trojan_Unnamed_2
{
strings:
	$a0 = { fe8bae330281c5030133f6e80000e800005d8b9e2502b440cd21b801578b9e25028b8e29028b }


condition:
	$a0
}