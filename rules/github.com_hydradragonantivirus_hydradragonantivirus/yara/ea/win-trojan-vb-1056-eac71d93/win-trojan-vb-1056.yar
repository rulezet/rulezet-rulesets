rule Win_Trojan_VB_1056
{
strings:
	$a0 = { 68bc174000e8eeffffff0000000000003000000040 }

	$a1 = { 534d5320426f6d626572206279204c69646c6f736573 }


condition:
	$a0 and $a1
}