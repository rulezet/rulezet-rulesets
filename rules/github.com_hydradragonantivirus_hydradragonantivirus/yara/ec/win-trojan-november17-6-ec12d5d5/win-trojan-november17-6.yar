rule Win_Trojan_November17_6
{
strings:
	$a0 = { 8b0150cb33c08ed80e07bf1604be8400a5a5be6e04a5c7 }


condition:
	$a0
}